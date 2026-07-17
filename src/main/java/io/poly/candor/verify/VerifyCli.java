package io.poly.candor.verify;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import io.poly.candor.verify.HonestyCheck.Result;
import io.poly.candor.verify.HonestyCheck.TraceEvent;
import io.poly.candor.verify.HonestyCheck.Violation;

/**
 * ⟨verify⟩ The {@code candor-java verify} DYNAMIC HONESTY ORACLE cli — the JVM analog of candor-ts's
 * verify.mjs. It runs a program under this jar's bytecode-instrumentation agent (see {@link Agent}) and
 * checks candor's STATIC report against what actually ran: {@code observed(f) ⊆ inferred(f) ∪ {Unknown}}
 * per executed method. A cardinal-sin VIOLATION exits 1.
 *
 * <pre>
 *   candor-java verify [&lt;classdir-or-jar&gt;] --run "&lt;cmd&gt;" [--report &lt;json&gt;] [--scope direct|all] [--json]
 * </pre>
 *
 * <p>Mechanism: it (a) resolves the report, (b) computes the include-class set from the report's fns and
 * writes it to a temp file, (c) finds THIS running jar, (d) runs {@code --run} with
 * {@code JAVA_TOOL_OPTIONS=-javaagent:<jar>=<includeFile> …} + {@code CANDOR_VERIFY_TRACE=<temp>} so every
 * spawned JVM records, (e) reads the trace, runs {@link HonestyCheck}, prints the verdict, exits 1 on a
 * violation. It shares no code with candor's static classifier — it observes reality.
 */
public final class VerifyCli {

    private VerifyCli() {}

    /** Entry point from {@code Candor.main} for {@code args[0].equals("verify")}. Calls System.exit itself. */
    public static void main(String[] args) {
        String dir = null, runCmd = null, reportArg = null, scope = "direct";
        boolean wantJson = false;
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--run" -> runCmd = i + 1 < args.length ? args[++i] : null;
                case "--report" -> reportArg = i + 1 < args.length ? args[++i] : null;
                case "--scope" -> scope = i + 1 < args.length ? args[++i] : scope;
                case "--json" -> wantJson = true;
                case "-h", "--help" -> usage(null);
                default -> {
                    if (a.startsWith("-")) usage("unknown flag " + a);
                    else if (dir == null) dir = a;
                    else usage("unexpected argument " + a);
                }
            }
        }
        if (runCmd == null) usage("missing --run <cmd> (the command that exercises the code)");
        if (!scope.equals("direct") && !scope.equals("all")) usage("--scope must be direct|all (got " + scope + ")");

        Path rootDir = Path.of(dir == null ? "." : dir).toAbsolutePath().normalize();

        // (a) resolve the report — --report <file>, else discover <dir>/.candor/report.*.json.
        Path reportPath = reportArg != null ? Path.of(reportArg) : discoverReport(rootDir);
        if (reportPath == null || !Files.isRegularFile(reportPath)) {
            usage("no report found" + (reportArg != null ? " at " + reportArg : " under " + rootDir + "/.candor")
                    + " — scan the project first (candor-java " + rootDir + " --json <file>) so verify has a claim to check");
        }
        JsonElement report;
        try {
            report = JsonParser.parseString(Files.readString(reportPath));
        } catch (IOException e) {
            usage("cannot read report " + reportPath + ": " + e.getMessage());
            return; // unreachable (usage exits) — for the compiler
        }
        Map<String, Set<String>> reportMap = HonestyCheck.reportEffects(report);

        // (b) include set = the distinct dotted CLASS of each report fn (a.b.C.m → a.b.C). Write to a temp file.
        Set<String> includeClasses = new LinkedHashSet<>();
        for (String fn : reportMap.keySet()) {
            int dot = fn.lastIndexOf('.');
            if (dot > 0) includeClasses.add(fn.substring(0, dot));
        }
        Path includeFile, traceFile;
        try {
            includeFile = Files.createTempFile("candor-verify-include-", ".txt");
            traceFile = Files.createTempFile("candor-verify-trace-", ".ndjson");
            Files.write(includeFile, includeClasses);
            Files.write(traceFile, new byte[0]); // fresh, empty
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        // (c) find THIS running jar (the agent). getCodeSource → a file; must be a real .jar for -javaagent.
        String jar = locateJar();
        if (jar == null) {
            System.err.println("candor verify: cannot locate the candor jar to use as the -javaagent — "
                    + "run `candor-java verify` from the built shadowJar (java -jar candor-java-*-all.jar verify …), "
                    + "or set CANDOR_JAVA_JAR to its path. (The agent needs a jar with the Premain-Class manifest; "
                    + "a classes dir cannot be a javaagent.)");
            System.exit(2);
        }

        // (d) run --run with the agent + trace wired via JAVA_TOOL_OPTIONS so every spawned JVM records.
        List<String> cmd = List.of("/bin/sh", "-c", runCmd);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.inheritIO();
        Map<String, String> env = pb.environment();
        String prior = env.getOrDefault("JAVA_TOOL_OPTIONS", "");
        String agentOpt = "-javaagent:" + jar + "=" + includeFile;
        env.put("JAVA_TOOL_OPTIONS", agentOpt + (prior.isEmpty() ? "" : " " + prior));
        env.put("CANDOR_VERIFY_TRACE", traceFile.toString());

        int programExit;
        try {
            if (!wantJson) {
                System.err.println("candor verify: running `" + runCmd + "` under the honesty oracle (scope: " + scope + ")…");
            }
            programExit = pb.start().waitFor();
        } catch (IOException | InterruptedException e) {
            usage("could not run `" + runCmd + "`: " + e.getMessage());
            return;
        }

        // (e) read the trace, run the check.
        List<TraceEvent> events = readTrace(traceFile);
        try { Files.deleteIfExists(includeFile); Files.deleteIfExists(traceFile); } catch (IOException ignored) { /* best effort */ }

        Result result = HonestyCheck.honestyCheck(reportMap,
                HonestyCheck.observedByFn(events, scope), scope);
        int analyzedTotal = reportMap.size();

        if (wantJson) {
            System.out.println(toJson(result, analyzedTotal, programExit));
        } else {
            printHuman(result, analyzedTotal, runCmd, programExit);
        }
        System.exit(result.honestyInvariantHolds ? 0 : 1);
    }

    // ── report discovery ────────────────────────────────────────────────────────────────────────────

    /** Discover a report under {@code <dir>/.candor/}: prefer {@code report.json}, else the first
     *  {@code report.*.json} (the {@code report.<pkg>.<backend>.json} convention). */
    private static Path discoverReport(Path rootDir) {
        Path candorDir = rootDir.resolve(".candor");
        Path canonical = candorDir.resolve("report.json");
        if (Files.isRegularFile(canonical)) return canonical;
        if (!Files.isDirectory(candorDir)) return null;
        try (var s = Files.list(candorDir)) {
            return s.filter(p -> {
                        String n = p.getFileName().toString();
                        return n.startsWith("report.") && n.endsWith(".json")
                                && !n.endsWith(".callgraph.json") && !n.endsWith(".hierarchy.json");
                    })
                    .sorted()
                    .findFirst().orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    // ── jar location ────────────────────────────────────────────────────────────────────────────────

    /** The path to THIS running jar (for {@code -javaagent}), or null when running from a classes dir. */
    private static String locateJar() {
        String env = System.getenv("CANDOR_JAVA_JAR");
        if (env != null && !env.isEmpty() && Files.isRegularFile(Path.of(env))) return env;
        try {
            var src = VerifyCli.class.getProtectionDomain().getCodeSource();
            if (src == null) return null;
            Path p = Path.of(src.getLocation().toURI());
            if (Files.isRegularFile(p) && p.getFileName().toString().endsWith(".jar")) {
                return p.toString();
            }
        } catch (Exception ignored) {
            // fall through — a classes-dir codesource (test run) has no jar
        }
        return null;
    }

    // ── trace reading ───────────────────────────────────────────────────────────────────────────────

    private static List<TraceEvent> readTrace(Path traceFile) {
        List<TraceEvent> events = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(traceFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                JsonObject o = JsonParser.parseString(line).getAsJsonObject();
                String fn = o.has("fn") ? o.get("fn").getAsString() : null;
                String effect = o.has("effect") ? o.get("effect").getAsString() : null;
                if (fn != null) events.add(new TraceEvent(fn, effect));
            }
        } catch (IOException | RuntimeException e) {
            // no/partial trace — a vacuous or partial HOLD, disclosed by the executed-fn count
        }
        return events;
    }

    // ── output ──────────────────────────────────────────────────────────────────────────────────────

    private static String toJson(Result r, int analyzedTotal, int programExit) {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        JsonObject metrics = new JsonObject();
        metrics.addProperty("scope", r.scope);
        metrics.add("effectsInScope", gson.toJsonTree(r.effectsInScope));
        metrics.addProperty("executedFunctionsChecked", r.executedFunctionsChecked);
        metrics.addProperty("analyzedFunctionsTotal", analyzedTotal);
        metrics.addProperty("soundCompleteOk", r.soundCompleteOk);
        metrics.addProperty("disclosedPartial", r.disclosedPartial);
        metrics.addProperty("disclosedUnknownLoadBearing", r.disclosedUnknownLoadBearing);
        metrics.addProperty("cardinalSinViolations", r.cardinalSinViolations);
        metrics.addProperty("honestyInvariantHolds", r.honestyInvariantHolds);
        metrics.addProperty("programExitCode", programExit);
        JsonObject out = new JsonObject();
        out.add("metrics", metrics);
        out.add("violations", gson.toJsonTree(r.violations));
        return gson.toJson(out);
    }

    private static void printHuman(Result r, int analyzedTotal, String runCmd, int programExit) {
        boolean held = r.honestyInvariantHolds;
        System.out.println("candor verify [" + r.scope + "]: honesty invariant "
                + (held ? "HOLDS ✓" : "VIOLATED ✘")
                + " over " + r.executedFunctionsChecked + " executed fn(s) (of " + analyzedTotal + " analyzed)");
        System.out.println("  sound-complete ok       : " + r.soundCompleteOk);
        System.out.println("  disclosed-partial       : " + r.disclosedPartial
                + " (" + r.disclosedUnknownLoadBearing + " Unknown-load-bearing)");
        System.out.println("  cardinal-sin violations : " + r.cardinalSinViolations);
        for (Violation v : r.violations) {
            String inferred = v.inferred.isEmpty() ? "pure" : String.join(", ", v.inferred);
            System.out.println("    ✘ " + v.fn + ": ran { " + String.join(", ", v.observed)
                    + " } but candor declared complete { " + inferred
                    + " } → escaped { " + String.join(", ", v.escaped) + " }");
        }
        if (programExit != 0) {
            System.err.println("  note: `" + runCmd + "` exited " + programExit
                    + " — the trace may be partial (fewer functions exercised).");
        }
    }

    private static void usage(String msg) {
        if (msg != null) System.err.println("candor verify: " + msg);
        System.err.println("usage: candor-java verify [<classdir-or-jar>] --run \"<cmd>\" "
                + "[--report <json>] [--scope direct|all] [--json]");
        System.exit(2);
    }
}
