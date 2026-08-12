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
 *   candor-java verify [&lt;classdir-or-jar&gt;] --run "&lt;cmd&gt;" [--report &lt;json&gt;] [--scope direct|all] [--json] [--allow-run-failure]
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
        boolean allowRunFailure = false;
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                // SPEC §3.2 ⟨0.28⟩ "given no value": a flag-shaped next token is NOT a value — refuse it
                // (usage exits 2) rather than consume it, the same rule the scan CLI and the gate verb
                // carry. `--run --json` used to take `--json` as the command to execute.
                case "--run" -> { requireValue(args, i, a); runCmd = args[++i]; }
                case "--report" -> { requireValue(args, i, a); reportArg = args[++i]; }
                case "--scope" -> { requireValue(args, i, a); scope = args[++i]; }
                case "--json" -> wantJson = true;
                // A non-zero --run exit means the run did not complete cleanly — its trace may be PARTIAL, so a
                // clean all-clear cannot be certified over it (fail-closed by default, below). --allow-run-failure
                // is the escape hatch for a suite where some test failures are EXPECTED: the run's effects were
                // still fully exercised, so the verdict is kept (advisory), the non-zero exit only disclosed.
                case "--allow-run-failure" -> allowRunFailure = true;
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

        // (b) include set = the dotted CLASS of every ANALYZED fn — the CALLGRAPH node universe, which
        // INCLUDES pure classes the effectful-only report omits. A wholly-pure class that secretly performs an
        // effect at runtime would otherwise never be instrumented and its effect go unwitnessed — a false
        // all-clear. When no callgraph sidecar is present we fall back to the report's classes and DISCLOSE the
        // gap (parity with the ts arm's attributionComplete), failing the run closed.
        Set<String> analyzedFns = loadCallgraphNodes(reportPath); // all analyzed fn quals, or null if no sidecar
        boolean includeComplete = analyzedFns != null;
        Set<String> includeClasses = new LinkedHashSet<>();
        for (String fn : (analyzedFns != null ? analyzedFns : reportMap.keySet())) {
            String cls = classOf(fn);
            if (cls != null) includeClasses.add(cls);
        }
        // (b2) the UNCOVERED (invisible) package set — packages the bytecode calls into but candor's classifier
        // cannot see (the §2 `coverage` envelope, ⟨0.15⟩). An effect that reaches a leaf THROUGH such a package
        // is one candor's static chain legitimately breaks at (and disclosed via `invisible`): the transitive
        // attribution must not blame a project caller ACROSS that boundary, or it false-positives a "violation"
        // for any library using an unmodelled dep (found: commons-configuration2 CatalogResolver.getResolver →
        // xml.resolver ctor). Trace.emit stops attributing once its stack walk crosses an uncovered frame.
        List<String> uncoveredPkgs = uncoveredPackages(report);
        Path includeFile, traceFile, uncoveredFile;
        try {
            includeFile = Files.createTempFile("candor-verify-include-", ".txt");
            traceFile = Files.createTempFile("candor-verify-trace-", ".ndjson");
            uncoveredFile = Files.createTempFile("candor-verify-uncovered-", ".txt");
            Files.write(includeFile, includeClasses);
            Files.write(traceFile, new byte[0]); // fresh, empty
            Files.write(uncoveredFile, uncoveredPkgs);
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
        // stdin + stderr are always inherited so the run looks normal. In --json mode the program's own
        // STDOUT must be kept OFF our stdout — otherwise it interleaves with the verify JSON and a machine
        // consumer can't parse it (found corpus-testing: `name=Tom Baldwin` printed into the JSON). Discard it
        // then (its stderr still shows); in human mode inherit everything. Mirrors candor-ts-verify's
        // `stdio: ["inherit","ignore","inherit"]` under --json.
        pb.redirectInput(ProcessBuilder.Redirect.INHERIT);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectOutput(wantJson ? ProcessBuilder.Redirect.DISCARD : ProcessBuilder.Redirect.INHERIT);
        Map<String, String> env = pb.environment();
        String prior = env.getOrDefault("JAVA_TOOL_OPTIONS", "");
        String agentOpt = "-javaagent:" + jar + "=" + includeFile;
        env.put("JAVA_TOOL_OPTIONS", agentOpt + (prior.isEmpty() ? "" : " " + prior));
        env.put("CANDOR_VERIFY_TRACE", traceFile.toString());
        if (!uncoveredPkgs.isEmpty()) env.put("CANDOR_VERIFY_UNCOVERED", uncoveredFile.toString());

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
        try { Files.deleteIfExists(includeFile); Files.deleteIfExists(traceFile); Files.deleteIfExists(uncoveredFile); } catch (IOException ignored) { /* best effort */ }

        Result result = HonestyCheck.honestyCheck(reportMap,
                HonestyCheck.observedByFn(events, scope), scope);
        int analyzedTotal = reportMap.size();

        // Disclose the run's soundness limits (parity with the ts arm's attributionComplete): an effectful-only
        // include set (no callgraph ⇒ pure classes uninstrumented, a secret effect in one unwitnessed) and torn
        // trace lines (captured effects lost) both mean the all-clear is not sound → fail closed (exit 2 below).
        java.util.List<String> gaps = new java.util.ArrayList<>();
        if (!includeComplete) gaps.add("no callgraph sidecar (<stem>.callgraph.json) — the include set covers only "
                + "the effectful classes candor reported; a secret effect in a wholly-pure class is NOT instrumented "
                + "and would be missed (re-scan with --out to emit the callgraph)");
        if (lastTornLines > 0) gaps.add(lastTornLines + " trace line(s) were unparseable (torn/interleaved) — those "
                + "captured effects are lost");
        // A non-zero --run exit means the command did not complete cleanly (a crash — including one the agent
        // itself could cause — or a failing test suite), so the trace may be PARTIAL and a clean all-clear cannot
        // be certified over it: fail closed (exit 2), same posture as the incomplete-attribution cases above.
        // --allow-run-failure opts out for a suite with EXPECTED failures (effects still fully exercised): the
        // non-zero exit is then only disclosed (programExitCode in --json; the note below), never fails the verdict.
        if (programExit != 0 && !allowRunFailure) gaps.add("the --run command exited " + programExit
                + " (did not complete cleanly) — its trace may be partial, so a clean all-clear cannot be certified; "
                + "re-run once it exits 0, or pass --allow-run-failure if some failures are expected and the effects "
                + "were still fully exercised");
        if (!gaps.isEmpty()) {
            result.attributionComplete = false;
            result.attributionNote = String.join("; ", gaps) + " — not a sound all-clear";
        }

        if (wantJson) {
            System.out.println(toJson(result, analyzedTotal, programExit));
        } else {
            printHuman(result, analyzedTotal, runCmd, programExit);
        }
        // A real violation dominates (exit 1); else an unsound/incomplete run is fail-CLOSED exit 2 (the
        // completeness-manifest convention), never a bogus green exit 0 over a run that could have missed an effect.
        System.exit(result.honestyInvariantHolds ? (result.attributionComplete ? 0 : 2) : 1);
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
                                && !n.endsWith(".callgraph.json") && !n.endsWith(".hierarchy.json")
                                && !n.endsWith(".locs.json"); // the candor-ts span sidecar is NOT a report

                    })
                    .sorted()
                    .findFirst().orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    /** The dotted CLASS of a candor fn qual. Strips an overload `(params)` suffix FIRST — otherwise a dot
     *  INSIDE a parameter type (`a.b.C.m(x.y.Z,int)`) would be mistaken for the class/method boundary and
     *  mis-derive the class. Returns null for a qual with no class part (a bare `<module>`-style unit). */
    static String classOf(String fn) {
        int paren = fn.indexOf('(');
        String base = paren >= 0 ? fn.substring(0, paren) : fn;
        int dot = base.lastIndexOf('.');
        return dot > 0 ? base.substring(0, dot) : null;
    }

    /** The ANALYZED-fn universe = the keys of the `<stem>.callgraph.json` sidecar (§2.2 — it lists EVERY
     *  analyzed fn, pure ones included), or null when no readable sidecar sits next to the report. Used to
     *  instrument pure classes too (a secret effect in one is otherwise unwitnessed). */
    /** The report's `coverage.packages` — the packages the bytecode calls into that candor's classifier does
     *  not cover (the §2 coverage envelope). Empty when the field is absent (older reports / fully-covered
     *  scans). Passed to the agent so Trace.emit's transitive attribution stops at an uncovered boundary. */
    private static List<String> uncoveredPackages(JsonElement report) {
        List<String> out = new ArrayList<>();
        try {
            if (report != null && report.isJsonObject()) {
                JsonElement cov = report.getAsJsonObject().get("coverage");
                if (cov != null && cov.isJsonObject()) {
                    JsonObject co = cov.getAsJsonObject();
                    // Scan-report shape: `uncovered: [{name, calls}, …]`.
                    JsonElement unc = co.get("uncovered");
                    if (unc != null && unc.isJsonArray())
                        for (JsonElement e : unc.getAsJsonArray())
                            if (e != null && e.isJsonObject() && e.getAsJsonObject().has("name"))
                                out.add(e.getAsJsonObject().get("name").getAsString());
                    // Gate-json shape: `packages: ["a.b", …]` (uncovered is a count there).
                    JsonElement pkgs = co.get("packages");
                    if (pkgs != null && pkgs.isJsonArray())
                        for (JsonElement e : pkgs.getAsJsonArray())
                            if (e != null && e.isJsonPrimitive()) out.add(e.getAsString());
                }
            }
        } catch (RuntimeException ignored) { /* a malformed coverage field just yields no boundary — sound (no crediting) */ }
        return out;
    }

    private static Set<String> loadCallgraphNodes(Path reportPath) {
        String p = reportPath.toString();
        String cg = (p.endsWith(".json") ? p.substring(0, p.length() - 5) : p) + ".callgraph.json";
        Path cgPath = Path.of(cg);
        if (!Files.isRegularFile(cgPath)) return null;
        try {
            JsonObject o = JsonParser.parseString(Files.readString(cgPath)).getAsJsonObject();
            return new LinkedHashSet<>(o.keySet());
        } catch (IOException | RuntimeException e) {
            return null; // unreadable/corrupt sidecar → fall back to the report + disclose (never a silent pass)
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

    static int lastTornLines = 0; // torn/interleaved trace lines skipped by the most recent readTrace (disclosed)

    private static List<TraceEvent> readTrace(Path traceFile) {
        List<TraceEvent> events = new ArrayList<>();
        int torn = 0;
        try {
            for (String line : Files.readAllLines(traceFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                // Parse EACH line independently — a single torn/interleaved line (two spawned JVMs appending to
                // the shared trace) must NOT abort the loop and drop every later effect (a false all-clear).
                // Skip it, count it, keep the rest; the count is disclosed and fails the run closed.
                try {
                    JsonObject o = JsonParser.parseString(line).getAsJsonObject();
                    String fn = o.has("fn") ? o.get("fn").getAsString() : null;
                    String effect = o.has("effect") ? o.get("effect").getAsString() : null;
                    if (fn != null) events.add(new TraceEvent(fn, effect));
                } catch (RuntimeException e) {
                    torn++;
                }
            }
        } catch (IOException e) {
            // no trace file — a vacuous HOLD, disclosed by the executed-fn count
        }
        lastTornLines = torn;
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
        metrics.addProperty("attributionComplete", r.attributionComplete); // parity with the ts arm
        if (r.attributionNote != null) metrics.addProperty("attributionNote", r.attributionNote);
        metrics.addProperty("programExitCode", programExit);
        JsonObject out = new JsonObject();
        out.add("metrics", metrics);
        out.add("violations", gson.toJsonTree(r.violations));
        out.add("rows", gson.toJsonTree(r.rows)); // per-fn detail — parity with candor-ts-verify's JSON
        return gson.toJson(out);
    }

    private static void printHuman(Result r, int analyzedTotal, String runCmd, int programExit) {
        boolean held = r.honestyInvariantHolds;
        String tail = held && !r.attributionComplete ? " (attribution INCOMPLETE — see below)" : "";
        System.out.println("candor verify [" + r.scope + "]: honesty invariant "
                + (held ? "HOLDS ✓" : "VIOLATED ✘") + tail
                + " over " + r.executedFunctionsChecked + " executed fn(s) (of " + analyzedTotal + " analyzed)");
        if (!r.attributionComplete && r.attributionNote != null) System.out.println("  ⚠ " + r.attributionNote);
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

    /** SPEC §3.2 ⟨0.28⟩ — a value-taking flag whose next token is dash-prefixed (bare {@code -}
     *  excepted) has been GIVEN NO VALUE; consuming the token instead is the silent reinterpretation
     *  §6.2 forbids. Exits via {@link #usage} naming both the flag and the token that is not a value. */
    private static void requireValue(String[] args, int i, String flag) {
        if (i + 1 >= args.length) usage(flag + " was given no value");
        String v = args[i + 1];
        if (v.startsWith("-") && !v.equals("-"))
            usage(flag + " was given no value — the next token " + v + " is a flag (a value really "
                    + "named that is spelled ./" + v + ")");
    }

    private static void usage(String msg) {
        if (msg != null) System.err.println("candor verify: " + msg);
        System.err.println("usage: candor-java verify [<classdir-or-jar>] --run \"<cmd>\" "
                + "[--report <json>] [--scope direct|all] [--json] [--allow-run-failure]");
        System.err.println("       --allow-run-failure  keep the verdict when the --run command exits non-zero "
                + "(a suite with expected test failures); by default a non-clean run fails closed (exit 2)");
        System.exit(2);
    }
}
