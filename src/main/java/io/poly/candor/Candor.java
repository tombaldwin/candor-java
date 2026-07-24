package io.poly.candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.Interpreter;
import org.objectweb.asm.tree.analysis.Value;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;
import io.poly.candor.model.*;
import static io.poly.candor.Literals.*;
import static io.poly.candor.ReportWriter.*;
import static io.poly.candor.Cha.*;
import static io.poly.candor.Interp.*;
import static io.poly.candor.Policy.*;
import static io.poly.candor.Loader.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Rules.*;

/**
 * candor-java (prototype) — a candor-spec implementation for the JVM, via ASM bytecode.
 *
 * Resolves each call to its concrete target, classifies it, records per-method DIRECT effects +
 * call edges, then propagates to a transitive fixpoint. See https://github.com/tombaldwin/candor-spec.
 *
 * SPRING-AWARE: Spring hides effects in framework-woven/generated code (proxies for @Transactional,
 * synthesized Spring Data repositories) and breaks the call graph (reflective ingress). Pure bytecode
 * tracing misses all of it. So we read Spring's DECLARATIONS — annotations and template/repository
 * types — as effect sources. The framework's magic becomes the signal.
 *
 * TRUST CONTRACT (SPEC §4): what candor can't see is reported as `Unknown`, never assumed pure —
 * reflection / dynamic invocation, a `native` (JNI) body, and dispatch over a project interface/abstract
 * with no visible impl. CHA resolves interface/virtual dispatch over project types; constructors,
 * static initializers (`<clinit>`, via class-load trigger edges), and lambdas/method-refs all propagate
 * their effects. Conformance (CANDOR_STRICT) treats a bean's injected dependencies as its capabilities.
 * Residual gap (PRINCIPLES #7): dispatch over unrecognised non-project types is assumed pure (else
 * every `list.add()` floods) — known-effectful libraries are caught by the classifier.
 */
public class Candor {
    /** The candor-spec contract version this build implements (the report SCHEMA + AS-EFF codes),
     *  distinct from the engine build id (the report's `version`). Emitted as the envelope's `spec` so a
     *  consumer can see which contract a report conforms to. candor-java is the REFERENCE engine and MAY
     *  lead a minor rung (candor-spec §"Versioning policy" — the version ladder): it declares `0.16` (the
     *  0.16 rung is the callgraph-aware baseline guard — a formerly-PURE fn that turns effectful is now
     *  caught as a gain by keying existence on the baseline callgraph sidecar rather than the report, and
     *  an Unknown-ONLY gain is advisory rather than a regression; candor-java is the REFERENCE
     *  implementation. The prior 0.15 rung — the κ-coverage ledger riding the §2 `coverage` field — still
     *  applies) while a sibling may remain on an earlier floor and raise as it implements it. Additive-only,
     *  so an older consumer is unaffected. */
    static final String SPEC_VERSION = "0.23";

    static final String FS_UNKNOWN = "?";   // Fs reached with no recorded kind (cross-jar) -> make no read/write claim

    /** Where human-readable GATE output (AS-EFF diagnostics + the "no violations" line) is written. Defaults
     *  to stdout, but main() flips it to stderr in `--json` stdout mode so `candor <classes> --json --policy p
     *  | jq` sees PURE JSON on stdout (the report already went there). Mirrors the `sum` PrintStream pattern
     *  used for the first-run summary; routing the decision through one field keeps every diag()/no-violations
     *  call site honest without threading a stream through every gate checker's signature. */
    static PrintStream diagOut = System.out;

    /** `--gate-json <file>`: when on, every AS-EFF diagnostic is ALSO captured structurally (below) so the
     *  gate verdict can be re-emitted as machine JSON — the same source of truth the console + exit code use,
     *  never a re-derivation. Off by default (zero cost, byte-identical output). Single-run CLI state; the
     *  `--parallel`/reentrant paths don't set it. */
    static boolean gateCapture = false;
    static final java.util.List<java.util.Map<String, Object>> gateViolations = new java.util.ArrayList<>();

    /** The `.candor/config` layer (declarative alternative to the CANDOR_* env vars; env overrides it).
     *  Loaded in scan mode; an empty default so a direct runScan (tests, --parallel) reads no config file. */
    static Config config = Config.empty();


    /** Reject an unrecognized leading-dash argument (spec §6.2): a typo'd flag must FAIL with exit 2,
     *  never be silently ignored nor read as a positional path — the same gateless-green class as an
     *  unreadable policy file. Shared by main() and Query.run so the binary has ONE posture. */
    static void rejectUnknownFlag(String arg, java.util.Set<String> known, String usage) {
        // ANY `-`-prefixed token that isn't a known flag is a typo/newer-flag — FAIL with exit 2 rather than
        // silently drop it or read it as a path. This covers a bare `-` (candor reads no stdin, so `-` is
        // never a valid positional) AND a single-dash typo like `-strict`: the latter, matched only against
        // `--`/bare-`-` before, was swallowed as a positional and disarmed the CI gate at exit 0 (Fable-review
        // finding B — rust/ts/swift all reject a single-dash typo; java diverged).
        if (arg.startsWith("-") && !known.contains(arg)) {
            System.err.println("candor: unknown flag " + arg + " (usage: " + usage + ")");
            System.exit(2);
        }
    }

    /** Start the current thread's scan from a clean slate. All per-scan state lives on
     *  {@link AnalysisContext}; {@link AnalysisState#newContext()} installs a fresh one for THIS thread,
     *  so a second in-process scan can't double-count edges or inherit the prior run's
     *  repo/entity/clinit/rule sets. Because the context is thread-local, concurrent scans on different
     *  threads are isolated (LB-1b). The immutable Set.of(...) markers (REPO_MARKERS, AMBIENT,
     *  KNOWN_EFFECTS, INJECTION, PATH_CTOR_OWNERS) are constants, not state, and are left untouched. */
    static void resetState() {
        newContext();
    }

    /** The analysis core, factored out of {@link #main} so it is re-entrant (resets the thread's context
     *  first; safe to run concurrently on separate threads — the context is thread-local) and free of
     *  System.exit (so it is unit-testable in-process): reset state, load the target, index overloads
     *  + CHA subtypes, compute Spring types, chain CANDOR_DEPS, run per-method analysis, resolve
     *  literal-reflection edges, then return the inferred per-method effect sets from the fixpoint. */
    /** Programmatic override for CANDOR_CLOSED_WORLD (set by a test, or a future `--closed-world` flag),
     *  OR'd with the env var at scan setup. Default false → the env is the only source. */
    static boolean forceClosedWorld = false;

    static Map<String, EffectSet> runScan(Path target) throws IOException {
        resetState();
        List<ClassNode> classes = load(target);
        ctx().ALL = classes;
        for (ClassNode cn : classes) {
            ctx().projectClasses.add(cn.name);
            ctx().byName.put(cn.name, cn);
            String dc = cn.name.replace('/', '.');
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("<clinit>")) ctx().classesWithClinit.add(cn.name);
                // Record this name's descriptor so overloaded names can be disambiguated (methodId).
                // EXCLUDE compiler-generated bridge/synthetic forwarders (a covariant-return or generic
                // bridge `call()Object` beside the real `call()Integer`): they aren't real overloads —
                // counting them would split a UNIQUE method (every Callable/Comparable impl) into a
                // disambiguated id and break the bare-`class.method` the report/entry-point rows use.
                // The bridge body just forwards to the real method, so leaving both bare (re-collapsed)
                // is correct — its effect IS the real method's.
                if ((mn.access & (Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) continue;
                ctx().overloadDescs.computeIfAbsent(dc + "." + mn.name, k -> new HashSet<>()).add(mn.desc);
            }
        }
        buildSubtypeIndex(classes);
        computeSpringTypes(classes);
        computeStreamFieldOrigins(classes); // VALUE-PROVENANCE Phase 2: which stream fields are provably all-concrete
        // Cross-jar inheritance (candor-spec §2): load dependency reports named by CANDOR_DEPS BEFORE
        // analyze, so a call into an already-analyzed dependency inherits its effects (vs assumed-pure).
        loadCrossDeps(config.value("deps", "CANDOR_DEPS"), provenance()[0]);
        ctx().taintEnabled = config.flag("taint", Mode.TAINT.envVar()); // read before analyze (the pass runs per method)
        ctx().closedWorld = forceClosedWorld || config.flag("closed-world", "CANDOR_CLOSED_WORLD"); // opt-in: scanned set is complete
        ctx().unknownRatchet = config.flag("unknown-ratchet", "CANDOR_UNKNOWN_RATCHET"); // opt-in: a NEW Unknown vs baseline fails
        // Per-class fail-soft: an exotic/malformed class that throws ANYWHERE in analyze (e.g. a malformed
        // method descriptor that ASM validates only lazily in Type.getArgumentTypes — the 0.5.6 crash class,
        // re-surfaced via an overloaded-name path the desc.startsWith("(") guard doesn't catch) must NOT
        // abort the WHOLE scan and silently zero EVERY other class's analysis (a DoS). Skip + disclose the
        // one bad class, mirroring collectClasses's tolerance.
        int analyzeSkipped = 0; String firstAnalyzeErr = null;
        for (ClassNode cn : classes) {
            try {
                analyze(cn);
            } catch (Throwable t) {
                analyzeSkipped++;
                if (firstAnalyzeErr == null) firstAnalyzeErr = cn.name + ": " + t;
                // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): an un-analyzable class is unseen, not pure — disclose it
                // to a machine (report + gate verdict), so the gate fails closed rather than green over it.
                ctx().unanalyzed.put(cn.name, "class failed to analyze: " + t);
            }
        }
        if (analyzeSkipped > 0)
            System.err.printf("candor-java: skipped %d unanalyzable class(es) (e.g. %s)%n",
                    analyzeSkipped, firstAnalyzeErr);

        // Resolve literal-getMethod reflection: edge to the named method OF THE RECEIVER CLASS only —
        // `Helper.class.getMethod("strip")` → `Helper.strip`. A receiver we can't pin to a project
        // class (a runtime `obj.getClass()`, or an EXTERNAL `String.class`) forms NO edge: the §4
        // Unknown stands. Matching by global leaf-name suffix (the old code) fabricated an edge to an
        // unrelated same-named project method — the exact "candor never fabricates an effect" breach
        // candor-scan's own comments record removing. Unknown stays either way (reflection is opaque).
        for (String[] pair : ctx().reflectPairs) {
            String caller = pair[0], lit = pair[1], recv = pair[2];
            if (recv.isEmpty() || !ctx().projectClasses.contains(recv)) continue;
            String callee = recv.replace('/', '.') + "." + lit;
            if (ctx().edges.containsKey(callee)) ctx().edges.get(caller).add(callee);
        }

        // TRUE-FORWARDING resolution (after ALL classes analysed, so a force site can reach a field bound
        // in another class): edge each forcing method to the lambda(s) stored in the SPECIFIC field it
        // forces. Field-scoped, so a pure-init lazy's lambda contributes nothing and the reader stays pure.
        for (String[] pair : ctx().deferredForcePairs) {
            Set<String> lambdas = ctx().deferredFieldLambdas.get(pair[1]);
            if (lambdas != null) ctx().edges.computeIfAbsent(pair[0], k -> new HashSet<>()).addAll(lambdas);
        }

        // PRIVATE FUNCTIONAL-PARAM FORWARDING resolution (after ALL classes analysed, so every nestmate
        // call site of a private sink has been collected). For each sink whose param-SAM Unknown was
        // deferred: if every call site passed a resolvable PROJECT lambda (none opaque, ≥1 collected),
        // edge the sink to those bodies — their real effects propagate, the smear-Unknown is gone. Else
        // RESTORE the honest callback Unknown (a call site passed a field/param/external-ref, or the sink
        // is uncalled) — never silently pure.
        for (String sink : ctx().fwdSinkPending) {
            Set<String> lambdas = ctx().fwdSinkLambdas.get(sink);
            if (!ctx().fwdSinkOpaque.contains(sink) && lambdas != null && !lambdas.isEmpty()) {
                ctx().edges.computeIfAbsent(sink, k -> new HashSet<>()).addAll(lambdas);
            } else {
                ctx().direct.computeIfAbsent(sink, k -> EffectSet.empty()).add(Effect.UNKNOWN);
                String[] why = ctx().fwdSinkPendingWhy.get(sink);
                if (why != null) ctx().unknownWhy.computeIfAbsent(sink, k -> new TreeSet<>()).add(UnknownReason.parse(why[0]));
            }
        }

        return fixpoint();
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>] [--policy <file>] [--gate-json <file>]");
            System.err.println(
                    "       candor <show|where|callers|map|diff|containment|reachable|path|impact|blindspots|tour|gains|whatif|rewire> [args] [--report <locator>]");
            System.err.println("       candor parsepolicy <policy-file>");
            System.err.println("       candor --version | --agents | --help");
            System.exit(2);
        }
        // Read-only queries over a written report (no re-analysis) — the sibling of candor-query.
        if (Query.COMMANDS.contains(args[0])) {
            System.exit(Query.run(args));
        }
        // The agent contract for THE INSTALLED BUILD, baked into the jar as a resource — doc and
        // engine cannot drift (the §2.1 version-trust rule applied to documentation).
        if (args[0].equals("-h") || args[0].equals("--help")) {
            System.out.println("""
                    candor-java — the JVM effect analyzer. Compiled bytecode in, a capability map out.

                    The family's reference engine: point it at compiled classes or a jar —
                    Java, Kotlin, Scala, Groovy, anything that compiles to JVM bytecode — and it
                    emits the per-method effect report every candor engine shares. A call it cannot
                    resolve comes back Unknown, never silently pure: the map may say "don't know",
                    never a quiet "safe".

                    USAGE
                      candor <classes-or-jar> [options]         analyse compiled classes (target/classes,
                                                                build/classes/java/main, or a .jar)
                      candor <action> [args] [options]          query the discovered report (.candor/ walk-up,
                                                                $CANDOR_REPORT, or --report)
                      candor --parallel <out-dir> <target>...   scan many targets concurrently, one report each
                      candor parsepolicy <policy-file>          print a parsed policy file as canonical JSON

                    COMMON ACTIONS
                      where <Effect>            the functions that perform an effect
                      path <fn> <Effect>        the call path by which a function reaches an effect
                      callers <fn>              who calls a function, direct and transitive
                      tour [N]                  the N most surprising transitive reaches (default 10)
                      blindspots                the Unknown sources worth resolving, ranked by reach
                      gains <current> <base>    what a new version newly reaches (the supply-chain diff)
                      fix <fn> <Effect>         the boundary hoist that would clear a violation

                    ALL ACTIONS
                      show  where  callers  map  containment  diff  reachable  impact  blindspots
                      gains  path  tour  whatif  fix  fix-gate  unverified  rewire  parsepolicy

                    OPTIONS  (uniform across every engine)
                      --report <locator>        use this report instead of discovering .candor/
                      --policy <file>           enforce a policy file (deny/pure/allow/forbid) — exit 1
                                                on a violation, 2 if unreadable; honours $CANDOR_POLICY
                                                when the flag is absent
                      --json [<file>]           machine-readable output (the form an agent / MCP server
                                                consumes); on a scan, --json <file> writes the report there,
                                                bare --json prints it to stdout (pipeable — `candor <classes>
                                                --json | jq .`; report envelope only, no sidecars)
                      --gate-json <file>        write the structured gate verdict { spec, ok, violations }
                                                as JSON; `-` streams it to stdout
                      --agents                  print the agent contract embedded in this build (AGENTS.md)
                      -V, --version             print the build and spec version (offline)
                      -h, --help                show this help

                    EXAMPLES
                      candor build/libs/app.jar
                      candor target/classes --json report.json
                      candor where Db
                      candor path OrderService.render Net
                      candor app.jar --policy candor.policy --gate-json -

                    ENVIRONMENT
                      CANDOR_POLICY             policy file to enforce when --policy is absent
                      CANDOR_REPORT             report locator for queries when --report is absent
                      .candor/config            the declarative layer for the same settings, anchored to
                                                the scan target; the env vars override it

                    Docs: candor.poly.io   ·   Verify an install: candor doctor""");
            System.exit(0);
        }
        if (args[0].equals("--agents")) {
            try (var in = Candor.class.getResourceAsStream("/AGENTS.md")) {
                if (in == null) {
                    System.err.println("candor: the AGENTS.md resource is missing from this build");
                    System.exit(2);
                }
                System.out.println("<!-- candor-java " + provenance()[0]
                        + " · the agent contract for this installed version -->");
                System.out.write(in.readAllBytes());
                System.out.flush();
            }
            System.exit(0);
        }
        // `--version` — the clean RELEASE semver (the GitHub-tag / jar-filename axis) + spec, then the
        // upgrade line. No network: candor analyzes for the `Net` effect and must not perform it, so it
        // never phones home. Staying current is the AGENT's job — it reads this, then (it has network)
        // compares against GitHub releases and upgrades.
        if (args[0].equals("--version") || args[0].equals("-V")) {
            System.out.println("candor-java " + release() + " (spec " + SPEC_VERSION + ")");
            System.out.println("upgrade: jbang --fresh candor@tombaldwin/candor-java");
            System.exit(0);
        }
        // `--parallel <out-dir> <target>...` — scan many jars/dirs CONCURRENTLY, one report each, into
        // <out-dir>/<name>.json (+ .callgraph.json / .hierarchy.json sidecars). Each scan runs on its own
        // thread with its OWN thread-local AnalysisContext (LB-1b), so they never clobber each other; this
        // amortizes one JVM start across N targets (a multi-module build, or a CI sweep over several
        // artifacts). Each report is byte-identical to a standalone `candor <target> --json` of that target.
        if (args[0].equals("--parallel")) {
            if (args.length < 3) {
                System.err.println("usage: candor --parallel <out-dir> <target>...");
                System.err.println("  report-generation only — writes one report per target. GATING still");
                System.err.println("  needs a per-jar `candor <jar>` run with CANDOR_STRICT/POLICY/BASELINE.");
                System.exit(2);
            }
            Path outDir = Path.of(args[1]);
            try {
                Files.createDirectories(outDir);
            } catch (IOException e) {
                System.err.println("candor: cannot create out-dir " + outDir + ": " + e.getMessage());
                System.exit(2);
            }
            List<Path> targets = new ArrayList<>();
            for (int i = 2; i < args.length; i++) targets.add(Path.of(args[i]));
            // basename without a trailing archive extension; a directory keeps its name.
            java.util.function.Function<Path, String> baseOf =
                    t -> t.getFileName().toString().replaceFirst("(?i)\\.(jar|zip)$", "");
            // FAIL-FAST on output-name collisions: two targets with the same basename (moduleA/app.jar +
            // moduleB/app.jar, or foo.jar + foo.zip) would both write <out-dir>/<base>.json and silently
            // clobber each other. A silently-dropped report reads as a false PASS downstream — refuse.
            Map<String, Path> seen = new HashMap<>();
            for (Path t : targets) {
                Path prev = seen.putIfAbsent(baseOf.apply(t), t);
                if (prev != null) {
                    System.err.println("candor: --parallel output collision — `" + t + "` and `" + prev
                            + "` both map to " + baseOf.apply(t) + ".json; give them distinct names or scan separately");
                    System.exit(2);
                }
            }
            int threads = Math.max(1, Math.min(targets.size(), Runtime.getRuntime().availableProcessors()));
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            List<String> failures = new CopyOnWriteArrayList<>();
            for (Path t : targets) {
                pool.submit(() -> {
                    Path out = outDir.resolve(baseOf.apply(t) + ".json");
                    try {
                        if (!Files.exists(t)) { failures.add(t + " (no such path)"); return; }
                        writeReport(runScan(t), out.toString(), null);   // own thread → own ctx() (LB-1b)
                        System.out.println("  " + t + " -> " + out);
                    } catch (Throwable e) {
                        // Record ANY failure — incl. a RuntimeException/Error from a phase outside runScan's
                        // per-class fail-soft — so a crashing target can't silently vanish with a green
                        // exit. The single-target path crashes loudly; --parallel must be no less honest.
                        failures.add(t + " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
                    } finally {
                        AnalysisState.remove();   // don't pin this scan's context on the pooled thread
                    }
                });
            }
            pool.shutdown();
            try {
                if (!pool.awaitTermination(1, TimeUnit.HOURS)) pool.shutdownNow();
            } catch (InterruptedException e) {
                pool.shutdownNow();
                Thread.currentThread().interrupt();
            }
            if (!failures.isEmpty()) {
                System.err.println("candor: " + failures.size() + " of " + targets.size() + " target(s) failed:");
                for (String f : failures) System.err.println("  " + f);
                System.exit(1);
            }
            System.out.println("candor: scanned " + targets.size() + " target(s) into " + outDir);
            System.exit(0);
        }
        // `parsepolicy <file>` — dump the parsed CANDOR_POLICY as canonical JSON. Not a user workflow;
        // it exists so the cross-impl conformance suite can diff this engine's policy parse against the
        // Rust reference and prove the SPEC §6.2 grammar means the same thing in both.
        if (args[0].equals("parsepolicy")) {
            if (args.length < 2) { System.err.println("usage: candor parsepolicy <policy-file>"); System.exit(2); }
            ctx().denyRules.clear(); ctx().allowRules.clear(); ctx().forbidRules.clear();
            // ⟨0.19⟩ config-aware: discover `.candor/config` (or CANDOR_CONFIG) anchored to the policy file so
            // an `Unknown[<alias>]` resolves via a checked-in `unknown-alias` — the dump reflects real gate
            // resolution (and the four-way parsepolicy differential pins the expansion).
            Config pcfg = Config.forTarget(Path.of(args[1]));
            ctx().unknownAliases.putAll(pcfg.unknownAliases());
            ctx().netPartners.addAll(pcfg.netPartners());
            if (!parsePolicy(args[1])) { System.err.println("candor: cannot read policy " + args[1]); System.exit(2); }
            System.out.println(Query.policyJson());
            System.exit(0);
        }
        // `verify [<classdir-or-jar>] --run "<cmd>" [--report <json>] [--scope direct|all] [--json]` — the
        // DYNAMIC HONESTY ORACLE (the JVM analog of candor-ts verify.mjs). Runs the program under THIS jar's
        // bytecode-instrumentation agent (Premain-Class, injected via JAVA_TOOL_OPTIONS) and checks candor's
        // STATIC report against what actually ran — `observed(f) ⊆ inferred(f) ∪ {Unknown}` per executed
        // method; a cardinal-sin violation exits 1. Independent of the classifier by construction: it
        // observes the real JDK effect boundary, sharing no code with the static engine (io.poly.candor.verify).
        if (args[0].equals("verify")) {
            io.poly.candor.verify.VerifyCli.main(args); // calls System.exit itself
            return;
        }
        // `selftest-reentrant <dirty-target> <real-target> --json <file>` — the REENTRANCY gate. Not a
        // user workflow: it scans <dirty-target> first to populate every static accumulator, then scans
        // <real-target> in the SAME process and writes <real-target>'s report. If resetState() missed an
        // accumulator, the first scan's edges/repo/entity/rule state leak into the second and the report
        // diverges from a fresh-process scan of <real-target> — which soundness/reentrancy.sh diffs.
        if (args[0].equals("selftest-reentrant")) {
            String rj = null;
            for (int i = 3; i < args.length; i++) if (args[i].equals("--json") && i + 1 < args.length) rj = args[++i];
            if (args.length < 3 || rj == null) {
                System.err.println("usage: candor selftest-reentrant <dirty-target> <real-target> --json <file>");
                System.exit(2);
            }
            runScan(Path.of(args[1]));                       // dirty the statics
            var inferred = runScan(Path.of(args[2]));        // real scan must be independent of the above
            writeReport(inferred, rj, null);
            System.exit(0);
        }
        // The first arg is the scan target (a dir/jar) — a flag there is a typo or a newer-doc flag
        // an older jar doesn't know; fail loudly rather than scan a path named after it.
        var scanFlags = java.util.Set.of("--json", "--policy", "--gate-json"); // --agents handled above; the rest are unknown here
        rejectUnknownFlag(args[0], java.util.Set.of(), "candor <dir-or-jar> [--json <file>] [--policy <file>] [--gate-json <file>] | candor --agents");
        String jsonOut = null, policyArg = null, gateJson = null;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--gate-json")) {
                // Re-emit the gate verdict as machine JSON (the structured analog of the AS-EFF console
                // lines) → `{ spec, ok, violations:[{rule,fn,effects,detail}] }`. Powers the PR-native SARIF
                // reporter (integrations/github). A valueless OR flag-shaped value FAILS (exit 2): without
                // the dash-check, `--gate-json --policy arch.policy` swallowed `--policy` as the verdict
                // path and the displaced bare `arch.policy` was silently dropped — a GATELESS green run,
                // the exact state this whole surface exists to prevent. `-` (stdout) stays valid.
                boolean ok = i + 1 < args.length && (args[i + 1].equals("-") || !args[i + 1].startsWith("-"));
                if (!ok) { System.err.println("candor: --gate-json requires a value"); System.exit(2); }
                gateJson = args[++i];
                gateCapture = true;
                gateViolations.clear();   // clear HERE (single-threaded, before runScan) — not in resetState,
                                          // which --parallel calls concurrently across a thread pool.
            } else if (args[i].equals("--json")) {
                // `--json <file>` (a following non-flag arg) writes the report file + sidecars; bare
                // `--json` (last arg, or the next arg is a flag) streams the report ENVELOPE to stdout
                // (the "-" sentinel; no callgraph/hierarchy sidecars), matching the Rust reference. The
                // valueless form is no longer an error — it's the pipe form (`candor <classes> --json | jq`).
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) jsonOut = args[++i];
                else jsonOut = "-";
            } else if (args[i].equals("--policy")) {
                if (i + 1 >= args.length) { // same posture as --json: a valueless gate flag must FAIL,
                    System.err.println("candor: --policy requires a value"); // never silently run gateless
                    System.exit(2);
                }
                policyArg = args[++i];
            } else {
                rejectUnknownFlag(args[i], scanFlags, "candor <dir-or-jar> [--json <file>] [--policy <file>] [--gate-json <file>]");
                // A BARE unexpected token is the same failure class as an unknown flag: candor's scan
                // grammar has exactly ONE positional (args[0], the target), so a stray bare token here is
                // a displaced value (a flag above swallowed its neighbour) or a typo — silently dropping
                // it is how `--gate-json --policy arch.policy` ran gateless. FAIL, never ignore.
                System.err.println("candor: unexpected argument " + args[i]
                        + " (usage: candor <dir-or-jar> [--json <file>] [--policy <file>] [--gate-json <file>])");
                System.exit(2);
            }
        }

        // CRASH-SAFETY: a nonexistent path, or a corrupt/truncated/empty/uppercase-ext "jar", must not
        // dump a stack trace and exit 1 — the archive layer throws raw NoSuchFileException / ZipException
        // / ProviderNotFoundException (a RuntimeException, not IOException). Match the unreadable-policy
        // posture: a clean one-line diagnostic and exit 2.
        Path scanTarget = Path.of(args[0]);
        // Load `.candor/config` for this run, ANCHORED TO THE SCAN TARGET (walk up from target/classes to
        // the repo root's .candor/config) — never to the process CWD, which would make the "config travels
        // with the code" promise depend on where the command was launched from. The layer sits UNDER the
        // env vars (which sit under the CLI flags); configured-but-unreadable fails loud (exit 2).
        config = Config.forTarget(scanTarget);
        if (!Files.exists(scanTarget)) {
            System.err.println("candor: no such path: " + args[0]);
            System.err.println("        point candor at COMPILED classes (target/classes · build/classes/java/main) or a built .jar.");
            System.err.println("        no build yet? run `mvn -q compile` or `./gradlew classes` first.");
            System.exit(2);
        }
        Map<String, EffectSet> inferred;
        try {
            inferred = runScan(scanTarget);
        } catch (IOException | java.nio.file.ProviderNotFoundException e) {
            // Scoped to the file-read failures load() can raise: NoSuchFileException/ZipException
            // (IOException) + ProviderNotFoundException (a RuntimeException, for an unrecognized
            // archive). NOT a blanket `RuntimeException` catch — that would MASK a genuine analysis
            // bug (an NPE in analyze/fixpoint) as a file error, hiding an engine defect.
            System.err.println("candor: cannot read scan target " + args[0] + ": " + e.getMessage());
            System.exit(2);
            return; // unreachable — exit(2) above; satisfies the definite-assignment of `inferred`
        }
        // ⟨0.19⟩ reason-class aliases for the §6.2 gate — populated AFTER runScan (which resets ctx()), so the
        // config `unknown-alias` map survives for checkPolicy's parse. (Set pre-runScan it was silently wiped —
        // the alias resolved in `parsepolicy` but NOT the gate; caught by a corpus dogfood.)
        ctx().unknownAliases.putAll(config.unknownAliases());
        ctx().netPartners.addAll(config.netPartners()); // ⟨0.20⟩ Net destination-class known-partner hosts

        // Fail loud on an EMPTY scan: a path that exists but holds no .class files (a source dir, an
        // unbuilt module, or a failed build) would otherwise report "0 functions reach effects" — which
        // reads as a clean, pure project rather than "nothing was analyzed", and would let a gate pass
        // trivially on a build that never produced bytecode. candor reads bytecode, not source.
        if (ctx().ALL.isEmpty()) {
            System.err.println("candor: no .class files found under " + args[0] + " — nothing to analyze.");
            System.err.println("        candor reads BYTECODE, not source — point it at COMPILED output");
            System.err.println("        (target/classes · build/classes/java/main) or a built .jar.");
            System.err.println("        no build yet? run `mvn -q compile` or `./gradlew classes` first.");
            System.exit(2);
        }

        // JSON output is orthogonal — write first so `--json` can snapshot a baseline. The report needs
        // the all-classes ClassConformance; compute it once here so the gate below can reuse it rather
        // than recompute (the §5 two-pass walk) on a --json + CANDOR_STRICT run.
        ClassConformance ccFull = (jsonOut != null) ? classConformance(inferred) : null;
        if (jsonOut != null) {
            try {
                writeReport(inferred, jsonOut, ccFull);
            } catch (IOException e) {
                // Same one-line-diagnostic + exit 2 posture as an unreadable scan target above: an
                // unwritable report path (a missing directory, a permission wall) is a misconfiguration,
                // not an engine crash — never a raw stack trace, and never exit 1 (that reads as a gate
                // violation to CI).
                System.err.println("candor: cannot write report " + jsonOut + ": " + e.getMessage());
                System.exit(2);
            }
        }

        // The κ-coverage disclosure (mirrors the Rust/TS receipts): external packages the bytecode
        // demonstrably calls where the classifier never fired — invisible, not Unknown. Per-scan
        // evidence instead of a doc footnote; never conclude "no effect" through a package named here.
        // ⟨0.15 staged⟩ the SAME ledger (one computation, kappaUncovered) also rides the report envelope
        // (`coverage`, ReportWriter) and the --gate-json advisory below — stderr line unchanged.
        List<Map.Entry<String, Integer>> unlisted = kappaUncovered();
        if (!unlisted.isEmpty()) {
            String shown = unlisted.stream().limit(8)
                    .map(e -> e.getKey() + " (" + e.getValue() + " call" + (e.getValue() == 1 ? "" : "s") + ")")
                    .collect(Collectors.joining(", "));
            String more = unlisted.size() > 8 ? " + " + (unlisted.size() - 8) + " more" : "";
            System.err.printf("candor-java: candor's classifier doesn't cover %d package%s this code calls into — "
                    + "their effects are INVISIBLE to the scan (absent from the report, NOT a claim they're pure): %s%s%n",
                    unlisted.size(), unlisted.size() == 1 ? "" : "s", shown, more);

        }

        // CLOSED-WORLD HAZARD GUARD. `closed-world` asserts "the scanned classes ARE the complete world",
        // which licenses resolving a would-be-broad dispatch to the visible impls instead of disclosing
        // Unknown. The trigger is the set of owners where the flag ACTUALLY CHANGED THE ANSWER — not the
        // κ ledger, which is a different gap entirely (an owner in an uncovered package is never
        // closed-world-resolved, since resolution requires the owner in `byName`). Triggering on the
        // ledger both MISSED the load-bearing case — a self-contained app whose own broad interface is
        // silently resolved, with nothing uncovered to report — and misnamed the mechanism. The hazard is
        // real whenever this fires: if ANY listed owner has an implementor in code the scan never loaded,
        // its resolved answer can read PURE where a real effect lives. Measured on a real 18.7k-fn webapp:
        // app classes ONLY under closed-world reported 618 gate hits where the same app scanned WITH its
        // 222 dependency jars honestly reports ~6.7k — the flag had silenced the library reaches. We warn
        // rather than refuse (the disclosure posture informs), and a user who genuinely scanned the whole
        // world is legitimately served by the flag — the remedy line tells the other user what to do.
        if (!ctx().closedWorldResolvedOwners.isEmpty()) {
            int n = ctx().closedWorldResolvedOwners.size();
            String top = ctx().closedWorldResolvedOwners.stream().limit(3)
                    .map(s -> s.replace('/', '.')).collect(Collectors.joining(", "));
            System.err.printf("candor-java: ⚠ closed-world resolved %d broad dispatch owner%s that would otherwise "
                    + "have disclosed Unknown (%s%s). If any of them has an implementor outside this scan, that "
                    + "resolution reads PURE where a real effect lives — a false all-clear. Only keep closed-world "
                    + "if the scan really is the whole world (the .war/.jar AND its dependency jars).%n",
                    n, n == 1 ? "" : "s", top, n > 3 ? ", …" : "");
        }

        // SCAN-COMPLETENESS NUDGE. A scan pointed at `build/classes` alone sees the app but none of its
        // dependencies, so the effects those dependencies perform are INVISIBLE (κ ledger above) — a
        // MISSING INPUT, not a precision defect. Measured on a real 18.7k-fn webapp: scanned app-only it
        // could PROVE Net on 465 functions; re-scanned as the deployed war (app + its 222 dependency
        // jars) the same gate proved Net on 5,865 — the library reaches became visible, determined
        // effects rather than nothing. (The nudge deliberately promises VISIBILITY, not dispatch
        // resolution: on that app 23 of 26 unresolved dispatches were over the app's OWN broad
        // hierarchies, which more bytecode does not fix.) Advisory only; never touches the verdict.
        // Triggered on CALL VOLUME into unscanned code, not on package count: count is the wrong metric —
        // candor's own `build/classes` calls 518 times into just 4 unscanned packages (gson, asm), the
        // textbook "you pointed it at classes, not the artifact" scan, which a count threshold misses
        // entirely, while a small app touching 5 tiny util packages would be nudged for nothing.
        int uncoveredCalls = unlisted.stream().mapToInt(Map.Entry::getValue).sum();
        if (uncoveredCalls >= UNCOVERED_CALLS_NUDGE_MIN)
            System.err.printf("candor-java: hint — %d call%s go into %d package%s that %s not scanned, so their "
                    + "effects are invisible here. If you scanned only your app's classes, point candor at the "
                    + "full deployed artifact (the .war/.jar AND its dependency jars): those reaches then resolve "
                    + "to DETERMINED effects instead of being absent.%n",
                    uncoveredCalls, uncoveredCalls == 1 ? "" : "s",
                    unlisted.size(), unlisted.size() == 1 ? "" : "s", unlisted.size() == 1 ? "is" : "are");

        // Gate modes (candor-spec §3), each selected by its Mode's env var: CANDOR_STRICT (conformance
        // via DI), CANDOR_BASELINE (regression guard), CANDOR_NO_AMBIENT, CANDOR_POLICY.
        // Gate modes resolve through the config layer: CLI flag → CANDOR_* env → .candor/config → default.
        String strict = config.value("strict", Mode.CONFORMANCE.envVar());
        String baseline = config.value("baseline", Mode.BASELINE.envVar());
        String noAmbient = config.value("no-ambient", Mode.NO_AMBIENT.envVar());
        String policy = policyArg != null ? policyArg : config.value("policy", Mode.POLICY.envVar()); // --policy takes precedence
        boolean enforce = baseline != null || noAmbient != null || strict != null || policy != null
                || ctx().taintEnabled || gateJson != null;   // --gate-json always emits its verdict (ok:true,[] when nothing to gate)

        // When stdout carries a JSON document — the report (`--json -`) OR the gate verdict
        // (`--gate-json -`) — it MUST stay pure JSON: route ALL human GATE output to stderr (the AS-EFF
        // diagnostics via diag() and the "no violations" line). The earlier --json fix missed the gate
        // path; the --gate-json - case was found by review: the AS-EFF lines interleaved the streamed
        // verdict, so `… --gate-json - | candor-sarif` got unparseable stdout. (Exit codes unaffected.)
        PrintStream gate = "-".equals(jsonOut) || "-".equals(gateJson) ? System.err : System.out;
        diagOut = gate;

        if (!enforce) {
            // First-run summary — totals by effect + Unknown, printed ALWAYS so the result is visible at a
            // glance (the deterministic payoff AGENTS.md §1a asks the agent for, now guaranteed by the engine).
            var effectful = inferred.entrySet().stream()
                    .filter(e -> !e.getValue().isEmpty()).collect(Collectors.toList());
            Map<String, Integer> counts = new HashMap<>();
            Set<String> classes = new HashSet<>();
            for (var e : effectful) {
                for (String x : e.getValue().toNames()) counts.merge(x, 1, Integer::sum);
                int dot = e.getKey().lastIndexOf('.');
                classes.add(dot > 0 ? e.getKey().substring(0, dot) : e.getKey());
            }
            int unknown = counts.getOrDefault("Unknown", 0);
            String breakdown = Stream.of("Net", "Llm", "Fs", "Db", "Exec", "Ipc", "Env", "Clipboard", "Clock", "Log", "Rand")
                    .filter(k -> counts.getOrDefault(k, 0) > 0)
                    .map(k -> k + " " + counts.get(k)).collect(Collectors.joining(" · "));
            // In --json-stdout mode stdout MUST be pure JSON (the report already went there) — route this
            // human effect summary to stderr so `candor <classes> --json | jq .` parses.
            PrintStream sum = "-".equals(jsonOut) ? System.err : System.out;
            sum.printf("candor — %,d function%s reach effects, across %,d class%s (pure functions omitted)%n",
                    effectful.size(), effectful.size() == 1 ? "" : "s", classes.size(), classes.size() == 1 ? "" : "es");
            if (!breakdown.isEmpty() || unknown > 0) {
                sum.println("  " + breakdown
                        + (unknown > 0 ? (breakdown.isEmpty() ? "" : "   ·   ") + "Unknown " + unknown + " (disclosed)" : ""));
            }
            // The "full map in <file>" pointer only makes sense for a written file — skip it in stdout mode.
            if (jsonOut != null && !"-".equals(jsonOut)) {
                sum.println("  full map in " + jsonOut + " — query it: candor-query callers <fn> / where <Effect>");
            }
            sum.println();

            // The cold-repo hook: after the effect summary + the κ-coverage ledger, emit ONE more stderr
            // line — the single most SURPRISING transitive reach (a benign-named function inheriting a
            // boundary effect a few hops away) + a ready-to-run `candor path` command, or the honest
            // "nothing hidden" fallback. Deterministic, NO LLM — the EXACT port of the Rust reference's
            // surface.rs, so every engine surfaces the SAME reach on a shared fixture. Marker is `candor:`
            // (the brand voice, not `candor-java:`) and the suggested command is `candor path …` —
            // identical across engines. Only on an interactive (non-gating) run — a machine-parsed gate
            // never wants the prose opener (we are already inside `if (!enforce)`).
            Surface.emit(inferred, ctx().direct, ctx().edges, ctx().loc, System.err);

            // Per-method detail only when NOT writing a report file (the file already holds it) — keeps the
            // agent's --json run concise (summary only), while a human's bare scan still gets the full audit.
            if (jsonOut == null) {
                System.out.println("candor-java — effect audit (Spring-aware; Unknown for reflection/dispatch)\n");
                inferred.entrySet().stream()
                        .filter(e -> !e.getValue().isEmpty())
                        .sorted(Map.Entry.comparingByKey())
                        .forEach(e -> {
                            var d = ctx().direct.getOrDefault(e.getKey(), EffectSet.empty()).toNames();
                            String set = e.getValue().toNames().stream()
                                    .map(x -> d.contains(x) ? x : x + "*")
                                    .collect(Collectors.joining(", "));
                            String tag = ctx().entryPoints.contains(e.getKey()) ? "  [entry]" : "";
                            System.out.printf("  %-52s { %s }%s%n", e.getKey(), set, tag);
                        });
                System.out.println("\n(* = via callee, [entry] = framework-invoked entry point)");
            }
            return;
        }

        int violations = 0;
        if (strict != null) violations += (ccFull != null)
                ? checkConformance(ccFull, strict)        // reuse the report's full conformance
                : checkConformance(inferred, strict);     // gate-only: scope-filtered declared
        if (noAmbient != null) violations += checkNoAmbient(inferred, noAmbient);
        if (baseline != null) violations += checkBaseline(inferred, baseline);
        if (policy != null) violations += checkPolicy(inferred, policy);
        // AS-EFF-007 is a heuristic ADVISORY (spec §6): emit findings but never fail CI on its own.
        int advisories = ctx().taintEnabled ? checkTaint(inferred) : 0;
        if (violations == 0 && advisories == 0) gate.println("candor-java: no violations");
        // FAILURE-only pointer at the engine's own remedy verb: appended AFTER the AS-EFF lines, on the
        // SAME stream (`gate`), so a clean run stays byte-identical and the pinned violation-line shapes,
        // exit codes and --gate-json verdict are untouched (append-only, human channel only).
        if (violations > 0) gate.println("→ candor fix-gate names the remedy for each");
        writeGateJson(gateJson, violations);   // machine verdict (before exit) — clean run writes ok:true,[]
        if (violations > 0) System.exit(1); // fail CI
        // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): a CONFIGURED gate over code candor could NOT fully analyze
        // (skipped unparseable classes) cannot certify — exit 2 (could-not-evaluate), the fail-closed posture
        // (matches candor-scan's had_parse_failure). A real violation (exit 1, above) dominates. A bare scan
        // with NO gate does not exit 2 — it discloses `unanalyzed` in the report and stays exit 0.
        boolean gateConfigured = policy != null || noAmbient != null || baseline != null;
        if (gateConfigured && !ctx().unanalyzed.isEmpty()) {
            System.err.println("candor-java: gate NOT certified — " + ctx().unanalyzed.size()
                    + " class(es) could not be analyzed (see above); a gate cannot be green over unanalyzed code");
            System.exit(2);
        }
    }

    /** ⟨0.15 staged⟩ The κ-coverage ledger, computed the ONE shared way for its three consumers — the
     *  per-scan stderr disclosure, the report envelope's `coverage` field (ReportWriter), and the
     *  --gate-json advisory — so the three can never disagree on names or counts. An external package the
     *  bytecode demonstrably calls where the classifier never fired AND no chained dep report covers it:
     *  its effects are INVISIBLE to the scan (absent, NOT a claim of purity). Sorted by call count
     *  descending, then name (the stderr line's order, kept for the wire too). */
    static List<Map.Entry<String, Integer>> kappaUncovered() {
        return ctx().kappaSeen.entrySet().stream()
                .filter(e -> !ctx().kappaClassified.contains(e.getKey()) && !ctx().depCoveredPkgs.contains(e.getKey()))
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .collect(Collectors.toList());
    }

    /** `--gate-json`: write the structured gate verdict `{ spec, ok, violations:[{rule,fn,effects,detail}] }` — the
     *  machine analog of the AS-EFF console lines, from the SAME diagnostics (captured in {@link #diag}), so
     *  it can never disagree with the exit code. `ok` is the CI verdict (advisory AS-EFF-007 lines appear in
     *  the list but do NOT clear `ok`). Consumed by the PR-native SARIF reporter (integrations/github). */
    static void writeGateJson(String path, int violations) {
        if (path == null) return;
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("spec", SPEC_VERSION);
        // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): a gate over code candor could NOT fully analyze (skipped
        // unparseable classes) must NOT read green — their effects are invisible, so a `deny`/`pure` that
        // "passes" over them is a false-pure. `ok` requires BOTH no violation AND a complete analysis.
        boolean incomplete = !ctx().unanalyzed.isEmpty();
        out.put("ok", violations == 0 && !incomplete);
        // ⟨0.21⟩ (Gap 1) the analyzed-universe count, so a --gate-json consumer sees the scan's scope from the
        // verdict alone (mirrors the report envelope's `analyzed`).
        var an = new java.util.LinkedHashMap<String, Object>();
        an.put("count", ctx().edges.keySet().size());
        out.put("analyzed", an);
        out.put("violations", gateViolations);
        // ⟨0.21⟩ (Gap 2) the machine-legible incompleteness: the units candor couldn't analyze, so a CI/agent
        // reading the JSON learns WHY the gate can't certify — the stderr warning alone used to hide this from
        // a machine. `incomplete:true` + the list; the caller exits 2 (could-not-fully-evaluate). Tom's call
        // 2026-07-17: emit a structured reason on the incomplete path rather than nothing (refines §3.3.1 to
        // "no ok:true GUESS" — ok:false + incomplete:true is honest, never a fabricated pass).
        if (incomplete) {
            out.put("incomplete", true);
            List<Map<String, Object>> un = new ArrayList<>();
            for (var e : ctx().unanalyzed.entrySet()) {
                var m = new java.util.LinkedHashMap<String, Object>();
                m.put("path", e.getKey());
                m.put("reason", e.getValue());
                un.add(m);
            }
            out.put("unanalyzed", un);
        }
        // ⟨0.15 staged⟩ the coverage ADVISORY (COVERAGE-DESIGN §3): when the κ ledger is non-empty the
        // verdict discloses it — a gate verdict over partially-covered code must not read as total.
        // VERDICT-PRESERVING (the ⟨0.9⟩ provable-purity auto-disclosure precedent): ok/violations/exit
        // are untouched — a gate does NOT fail on uncovered deps (nearly every real scan has some); the
        // policy author sees the note and decides (`deny Unknown` stays the opt-in strict posture).
        // Omitted when fully covered, so that verdict stays byte-identical to a pre-⟨0.15⟩ one.
        List<Map.Entry<String, Integer>> uncov = kappaUncovered();
        if (!uncov.isEmpty()) {
            var cov = new java.util.LinkedHashMap<String, Object>();
            cov.put("uncovered", uncov.size());
            cov.put("packages", uncov.stream().map(Map.Entry::getKey).collect(Collectors.toList()));
            out.put("coverage", cov);
        }
        try {
            String json = io.poly.candor.model.ReportJson.pretty(out);
            if (path.equals("-")) System.out.println(json);
            else Files.writeString(Path.of(path), json + "\n");
        } catch (IOException e) {
            // FAIL-CLOSED: the verdict file is what a CI consumer (the SARIF reporter) reads — a clean
            // gate whose verdict could not be WRITTEN must not exit 0, or the pipeline reads "green, no
            // verdict" as a pass (the gateless-green class, same posture as an unreadable policy). With
            // violations pending the caller's exit 1 still wins (a real violation outranks the I/O error),
            // but the failure is loud either way.
            System.err.println("candor: could not write --gate-json " + path + ": " + e.getMessage());
            if (violations == 0) System.exit(2);
        }
    }

    /** Emit one AS-EFF diagnostic line (candor-spec §6) through the typed {@link DiagnosticCode}, so the
     *  code vocabulary is first-class rather than an inline string literal. {@code format} is the
     *  message body (no code prefix, no trailing newline); render() prepends {@code "[AS-EFF-00x] "}. */
    static void diag(DiagnosticCode code, String format, Object... args) {
        diagCapture(code, java.util.List.of(), java.util.List.of(), java.util.List.of(), format, args);
    }

    /** As the effect-bearing {@link #diag(DiagnosticCode, java.util.List, String, Object...)}, but also records
     *  the reason CLASSES on the offending fn — for an AS-EFF-006 `Unknown` denial, so a `--gate-json` consumer
     *  sees every reason the strict gate bit (SPEC §6.2 ⟨0.19⟩). Empty for any non-Unknown violation. */
    static void diag(DiagnosticCode code, java.util.List<String> effects, java.util.List<String> reasonClass,
                     String format, Object... args) {
        diagCapture(code, effects, reasonClass, java.util.List.of(), format, args);
    }

    /** As above, plus the fn's Net destination classes (SPEC §6.2 ⟨0.20⟩) — recorded when {@code Net} is
     *  denied, so a --gate-json consumer sees which destination classes the security gate bit. */
    static void diag(DiagnosticCode code, java.util.List<String> effects, java.util.List<String> reasonClass,
                     java.util.List<String> netClass, String format, Object... args) {
        diagCapture(code, effects, reasonClass, netClass, format, args);
    }

    /** As {@link #diag(DiagnosticCode, String, Object...)}, but records the specific effect(s) the violation
     *  concerns — the DENIED/gained/undeclared set (the intersection of what the entity does and what the
     *  rule forbids), which a consumer cannot reconstruct from the report's per-fn `direct` set. Used by the
     *  effect-bearing codes; a layer-flow (009) / unresolved (003) code carries no effect and uses the plain
     *  form. */
    static void diag(DiagnosticCode code, java.util.List<String> effects, String format, Object... args) {
        diagCapture(code, effects, java.util.List.of(), java.util.List.of(), format, args);
    }

    private static void diagCapture(DiagnosticCode code, java.util.List<String> effects,
                                    java.util.List<String> reasonClass, java.util.List<String> netClass,
                                    String format, Object... args) {
        String body = String.format(format, args);
        diagOut.println(new Diagnostic(code, body).render());
        // --gate-json capture: EVERY AS-EFF site passes the offending entity (a fn, or a class for the
        // conformance codes) as args[0], recorded structurally here — one site, all codes, no console
        // parsing. `effects` is the specific effect set the violation is about (empty for a layer-flow /
        // unresolved code); `detail` is the message body. Consumers join `loc` from the report by `fn`.
        if (gateCapture && args.length > 0 && args[0] instanceof String fn) {
            var m = new java.util.LinkedHashMap<String, Object>();
            m.put("rule", code.code());
            m.put("fn", fn);
            m.put("effects", effects);
            m.put("detail", body);
            // ⟨0.19⟩ reason-scoped Unknown: the fn's reason classes when Unknown is denied (SPEC §6.2). Omitted
            // when empty, so a non-Unknown violation's verdict is byte-identical to pre-feature.
            if (!reasonClass.isEmpty()) m.put("reasonClass", reasonClass);
            // ⟨0.20⟩ Net destination-class: the fn's destination classes when Net is denied (SPEC §6.2). Omitted
            // when empty, so a non-Net violation's verdict stays byte-identical to pre-feature.
            if (!netClass.isEmpty()) m.put("netClass", netClass);
            gateViolations.add(m);
        }
    }

    /** Conformance via dependency injection: a class's fields are the capabilities it holds, so its effects
     *  must be covered by what those collaborators provide. An effect performed beyond them means reaching
     *  for ambient authority instead of receiving it (AS-EFF-001) — candor's capability-token model in
     *  Java's idiom: a bean's signature (its dependencies) tells you its effect surface. */
    static int checkConformance(Map<String, EffectSet> inferred, String scope) {
        // Gate-only path: build performed/declared (candor-spec §5) the ONE shared way, with `declared`
        // scoped to in-scope classes (the gateScopeCovers skip below reads only those) — on a narrow
        // CANDOR_STRICT scope over a large jar that avoids a whole-jar field/type walk. When --json is also
        // set, main passes the full ClassConformance it already built for the report (checkConformance(cc,…)).
        return checkConformance(classConformance(inferred, scope), scope);
    }

    static int checkConformance(ClassConformance cc, String scope) {
        int v = 0;
        for (ClassNode cn : ctx().ALL) {
            String dc = cn.name.replace('/', '.');
            if (!gateScopeCovers(scope, dc)) continue;
            EffectSet declared = cc.declared().getOrDefault(dc, EffectSet.empty());
            EffectSet perf = cc.performed().getOrDefault(dc, EffectSet.empty());
            boolean hasUnknown = perf.hasUnknown();
            List<String> undeclared = perf.minus(declared).without(Effect.UNKNOWN).toNames();
            List<String> unused = declared.minus(perf).toNames();
            // SPEC §6: the PROGRAM entry point is exempt from AS-EFF-001 — it legitimately mints/holds
            // the whole capability bundle (the Rust reference exempts tcx.entry_fn). At this gate's class
            // granularity that is the class declaring `public static void main(String[])`, the composition
            // root. The exemption is 001-ONLY: an unused injected capability (002) and an unresolvable
            // call (003) are entry-point sins too. Framework roots (@GetMapping etc.) are NOT exempt —
            // the spec exempts the program entry, and a controller reaching past its beans is exactly
            // what this gate exists to catch. (Was missing entirely — found by the never-tested-surface
            // sweep; StrictConformanceGateTest pins it red-then-green.)
            boolean entryClass = cn.methods.stream().anyMatch(Candor::isProgramEntry);
            if (!undeclared.isEmpty() && !entryClass) {
                String have = declared.isEmpty() ? "no injected capability"
                        : "only { " + String.join(", ", declared.toNames()) + " }";
                diag(DiagnosticCode.AS_EFF_001, undeclared, "class `%s` performs { %s } but holds %s; "
                        + "inject a collaborator that provides it (don't reach for ambient authority)",
                        dc, String.join(", ", undeclared), have);
                v++;
            }
            if (hasUnknown) {
                diag(DiagnosticCode.AS_EFF_003, "class `%s` makes calls candor cannot resolve "
                        + "(reflection / unresolved dispatch); effect set not provably complete", dc);
                v++;
            }
            if (!unused.isEmpty()) {
                diag(DiagnosticCode.AS_EFF_002, unused, "class `%s` injects { %s } but never uses it",
                        dc, String.join(", ", unused));
                v++;
            }
        }
        return v;
    }

    /** Effects a field of type `internal` can supply (Spring repo/template, or a project collaborator). */
    static EffectSet typeEffects(String internal, Map<String, EffectSet> performed) {
        if (ctx().repoTypes.contains(internal)) return EffectSet.of(Effect.DB);
        if (ctx().feignTypes.contains(internal) || ctx().httpClientTypes.contains(internal)) return EffectSet.of(Effect.NET);
        String dotted = internal.replace('/', '.');
        EffectSet lib = classifyType(dotted);
        if (!lib.isEmpty()) return lib;
        if (ctx().byName.containsKey(internal)) return performed.getOrDefault(dotted, EffectSet.empty());
        return EffectSet.empty();
    }

    /** Type-level classification of a collaborator (mirrors the call-level classify, by owner type). */
    static EffectSet classifyType(String dotted) {
        if (dotted.equals("org.springframework.web.client.RestTemplate")
                || dotted.equals("org.springframework.web.client.RestClient")
                || dotted.startsWith("org.springframework.web.reactive.function.client.")
                || dotted.equals("org.springframework.jms.core.JmsTemplate")
                || dotted.equals("org.springframework.kafka.core.KafkaTemplate"))
            return EffectSet.of(Effect.NET);
        if (dotted.equals("org.springframework.jdbc.core.JdbcTemplate")
                || dotted.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                || dotted.equals("jakarta.persistence.EntityManager")
                || dotted.equals("javax.persistence.EntityManager"))
            return EffectSet.of(Effect.DB);
        return EffectSet.empty();
    }

    /** Per-class conformance inputs (candor-spec §5), shared by the JSON report and the AS-EFF gate so
     *  the model is computed ONE way: {@code performed} = union of inferred over each class's own
     *  methods; {@code declared} = effects the class's injected-dependency field types can supply
     *  ({@link #typeEffects}); {@code fnToClass} maps a method id to its declaring class. */
    record ClassConformance(Map<String, EffectSet> performed, Map<String, EffectSet> declared,
            Map<String, String> fnToClass) {}

    /** The report path needs {@code declared} for every class. */
    static ClassConformance classConformance(Map<String, EffectSet> inferred) {
        return classConformance(inferred, null);
    }

    /** {@code performed} is ALWAYS project-wide (typeEffects resolves a project collaborator through it,
     *  so a narrowed map would mis-derive declared). {@code declared} is built only for classes
     *  {@code declaredScope} covers ({@code null} = all) — the gate reads only its in-scope classes, and a
     *  class's declared set depends only on {@code performed}, never on another class's declared, so
     *  scoping it changes nothing the gate reads. */
    static ClassConformance classConformance(Map<String, EffectSet> inferred, String declaredScope) {
        Map<String, EffectSet> performed = new HashMap<>();
        Map<String, String> fnToClass = new HashMap<>();
        for (ClassNode cn : ctx().ALL) {
            String dc = cn.name.replace('/', '.');
            EffectSet p = performed.computeIfAbsent(dc, k -> EffectSet.empty());
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                String fn = methodId(dc, mn.name, mn.desc);
                fnToClass.put(fn, dc);
                EffectSet inf = inferred.get(fn);
                if (inf != null) p.addAll(inf);
            }
        }
        Map<String, EffectSet> declared = new HashMap<>();
        for (ClassNode cn : ctx().ALL) {
            String dc = cn.name.replace('/', '.');
            if (declaredScope != null && !gateScopeCovers(declaredScope, dc)) continue;
            EffectSet d = EffectSet.empty();
            if (cn.fields != null)
                for (FieldNode f : cn.fields) {
                    String t = fieldTypeInternal(f.desc);
                    if (t != null) d.addAll(typeEffects(t, performed));
                }
            declared.put(dc, d);
        }
        return new ClassConformance(performed, declared, fnToClass);
    }

    /** Object type internal name from a field descriptor (`Lcom/x/Foo;` -> `com/x/Foo`); null if primitive. */
    static String fieldTypeInternal(String desc) {
        int l = desc.indexOf('L');
        if (l >= 0 && desc.endsWith(";")) return desc.substring(l + 1, desc.length() - 1);
        return null;
    }


    /** Whether a CANDOR_* gate scope covers a dotted method/class name. The `1`/empty value is the
     *  whole-project flag; any other value is a real scope, matched through {@link #scopeMatches} so the
     *  gate scopes are SEGMENT- and `::`-aware exactly like the §6.2 policy gate. The old raw `startsWith`
     *  silently diverged — a `::`-written or non-prefix scope disabled the gate (a false PASS on a real
     *  ambient/strict violation) AND prefix-bled (`com.foo` matched `com.foobar`). */
    static boolean gateScopeCovers(String scope, String dottedName) {
        return scope.equals("1") || scope.isEmpty() || scopeMatches(dottedName, scope);
    }


    /** The per-method scan: registers each method's node, marks its runtime-invoked entry-point
     *  status, runs the per-method dataflow passes (taint, receiver provenance, const-string/URL
     *  locals), then walks the instructions dispatching to the per-instruction-kind handlers
     *  ({@link #handleMethodInsn}, {@link #handleNewInsn}, {@link #handleInvokeDynamic} — a static
     *  field access inlines to {@link #clinitEdge}). The shared per-method state travels as one
     *  {@link MethodScan}; the handlers run in the original inline-loop order (P7 decomposition —
     *  pure code motion, byte-identical output). */
    static void analyze(ClassNode cn) {
        AnalysisContext ctx = ctx();
        String dottedClass = cn.name.replace('/', '.');
        boolean classTx = annoPresent(cn.visibleAnnotations, TX);
        // Runtime-invoked overrides this class is eligible for: the RUNTIME_OVERRIDES rows whose
        // supertype-substring appears in this class's supertype chain (computed once per class). A
        // matching method declared here is then an entry point — the runtime invokes it, not project code.
        Set<String> supers = transSupers(cn.name);
        List<String[]> runtimeRows = RUNTIME_OVERRIDES.stream()
                .filter(r -> supers.stream().anyMatch(s -> supertypeMatches(s, r[0])))
                .toList();
        // Ktor route handler: a Kotlin suspend-lambda (`extends SuspendLambda`) whose receiver is a Ktor
        // request context (`io.ktor.server.routing.RoutingContext` in 3.x, `io.ktor.util.pipeline.
        // PipelineContext` in 2.x) — i.e. a `get("/x") { … }` body. Ktor invokes it from its request
        // pipeline with NO project call site (the lambda is registered, then run later on another thread),
        // so it's orphaned from reachability — the Kotlin analog of Spring @*Mapping, but a lambda with no
        // annotation/supertype marker. The tell: a method whose descriptor carries a Ktor context PARAMETER
        // (the erased generic is concrete on the `invoke` bridge). Mark this class's body method.
        boolean ktorHandler = supers.contains("kotlin/coroutines/jvm/internal/SuspendLambda")
                && cn.methods.stream().anyMatch(m ->
                        m.desc.contains("io/ktor/server/routing/RoutingContext")
                                || m.desc.contains("io/ktor/util/pipeline/PipelineContext"));
        for (MethodNode mn : cn.methods) {
            // Constructors (`<init>`) AND static initializers (`<clinit>`) are both analyzed: a `new X()`
            // edges to `X.<init>`, and a class-load trigger (`new`, a static call, a static field access)
            // edges to `X.<clinit>` (see below), so an effectful constructor OR static initializer
            // propagates to its use site instead of being silently pure.
            String id = methodId(dottedClass, mn.name, mn.desc);
            EffectSet dir = registerMethod(ctx, cn, mn, id);
            markEntryPoints(ctx, cn, mn, id, dir, classTx, supers, runtimeRows, ktorHandler);
            // Host/table literals are extracted PER host/SQL-bearing CALL (from each call's own argument
            // window — see literalArgsInWindow at the call sites below), not by a method-wide LDC sweep.
            // The per-call attribution mirrors candor-rust's `str_arg` and kills the AS-EFF-008 evasion
            // where a benign URL literal in a host-bearing method certified a runtime-computed host. The
            // const-local map lets the window resolve a literal that reaches the sink through a local.
            Map<Integer, String> constLocals = constStringLocals(mn);
            // URL/URI values provably built from a literal host — lets a split `URL u = new URL("h"); u.open
            // Stream()` still attribute its host (so the common literal case is not over-flagged), while a
            // runtime-built URL stays unattributable → the terminal reads incomplete (the URL split-construct
            // /use AS-EFF-008 fail-closed, replacing the old value-flow backlog at the Net surface below).
            Map<Integer, String> urlLocals = constUrlLocals(mn, constLocals);
            // This method's entry-point status is settled before the loop (entry detection above) and `id`
            // is fixed, so hoist it out of the per-instruction loop (used by the R17 gate below).
            MethodScan s = new MethodScan(mn, id, dir, taintFrames(ctx, cn, mn), provFrames(cn, mn),
                    constLocals, urlLocals, ctx.entryPoints.contains(id));
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode min) {
                    handleMethodInsn(ctx, s, min);
                } else if (insn instanceof TypeInsnNode tin && tin.getOpcode() == Opcodes.NEW) {
                    handleNewInsn(ctx, s, tin);
                } else if (insn instanceof FieldInsnNode fin
                        && (fin.getOpcode() == Opcodes.GETSTATIC || fin.getOpcode() == Opcodes.PUTSTATIC)) {
                    // A static field access triggers the owner's class-load → its `<clinit>` runs.
                    clinitEdge(id, fin.owner);
                } else if (insn instanceof InvokeDynamicInsnNode idin) {
                    handleInvokeDynamic(ctx, s, idin);
                }
            }
        }
    }

    /** Per-METHOD scan state shared by the per-instruction handlers — exactly what the original
     *  inline instruction loop closed over. One instance per analyzed method; the handlers unpack
     *  the fields they use under the original local names, so their bodies read (and diff) as the
     *  pre-split code. */
    static final class MethodScan {
        final MethodNode mn;
        final String id;                         // this method's node id (methodId)
        final EffectSet dir;                     // = ctx.direct.get(id), the direct-effect accumulator
        final Frame<TaintValue>[] taintFrames;   // AS-EFF-007 taint frames (null unless CANDOR_TAINT + analyzable)
        final Frame<ProvValue>[] provFrames;     // receiver-provenance frames (null on bodiless/failed)
        final Map<Integer, String> constLocals;  // local slot -> const String (the literal-window resolver)
        final Map<Integer, String> urlLocals;    // local slot -> URL/URI value with a literal host
        final boolean isEntry;                   // entry-point status, settled before the loop (R17 gate)
        MethodScan(MethodNode mn, String id, EffectSet dir, Frame<TaintValue>[] taintFrames,
                Frame<ProvValue>[] provFrames, Map<Integer, String> constLocals,
                Map<Integer, String> urlLocals, boolean isEntry) {
            this.mn = mn;
            this.id = id;
            this.dir = dir;
            this.taintFrames = taintFrames;
            this.provFrames = provFrames;
            this.constLocals = constLocals;
            this.urlLocals = urlLocals;
            this.isEntry = isEntry;
        }
    }

    /** Registers a method's node (effect set, edge set, source loc, cross-jar hash), binds any
     *  deferred-container fields its ctor/clinit stores, and marks a `native` body Unknown. */
    static EffectSet registerMethod(AnalysisContext ctx, ClassNode cn, MethodNode mn, String id) {
        var dir = ctx.direct.computeIfAbsent(id, k -> EffectSet.empty());
        ctx.edges.computeIfAbsent(id, k -> new HashSet<>());
        ctx.loc.putIfAbsent(id, cn.sourceFile + ":" + firstLine(mn));
        // Stable, descriptor-bearing cross-jar identity (candor-spec §2 `hash`): the exact ref a
        // call site in a dependent jar uses, so that jar can inherit this method's effects.
        ctx.hashOf.putIfAbsent(id, cn.name + "." + mn.name + mn.desc);

        // TRUE-FORWARDING bindings: in a constructor / static initializer, find each PUTFIELD/PUTSTATIC
        // whose stored value came from a recognised deferred-execution container construction
        // (`LazyKt.lazy(λ)`, `ThreadLocal.withInitial(λ)`, or a `new …LazyImpl(λ)`) whose argument is a
        // lambda/method-ref. Bind the field to that lambda body so a later FORCE of the field edges to it.
        if (mn.name.equals("<init>") || mn.name.equals("<clinit>"))
            bindDeferredFields(cn, mn);

        // A `native` method has no bytecode body — its JNI implementation could perform ANY effect,
        // exactly the opacity reflection has. Honest `Unknown`, never silent-pure (SPEC §4); else a
        // call into a project-declared native binding would look like a no-op.
        if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
            dir.add(Effect.UNKNOWN);
            ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>()).add(UnknownReason.of(UnknownReason.Kind.NATIVE, mn.name));
        }
        return dir;
    }

    /** The JVM program entry point, `static void main(String[])` — the ONE method the launcher invokes
     *  (SPEC §2 reachability root; SPEC §6 AS-EFF-001 exemption). Shape-exact: an instance `main`, or a
     *  static `main` with any other descriptor, is an ordinary method (the lookalike twin stays gated). */
    static boolean isProgramEntry(MethodNode mn) {
        return mn.name.equals("main") && mn.desc.equals("([Ljava/lang/String;)V")
                && (mn.access & Opcodes.ACC_STATIC) != 0;
    }

    /** Entry-point detection for one method — every runtime-invoked root: Spring/composed
     *  annotations, CDI observers, gRPC handlers, `finalize`, serialization callbacks, `main`,
     *  the RUNTIME_OVERRIDES rows, and Ktor handler bodies. Also the declarative @Transactional
     *  → Db effect (kept first: original block order). */
    static void markEntryPoints(AnalysisContext ctx, ClassNode cn, MethodNode mn, String id, EffectSet dir,
            boolean classTx, Set<String> supers, List<String[]> runtimeRows, boolean ktorHandler) {
        // Spring annotations on this method (the effect Spring's proxy/generated code performs).
        if (classTx || annoPresent(mn.visibleAnnotations, TX)) dir.add(Effect.DB);
        // META-ANNOTATION aware: a method carrying a COMPOSED annotation (Spring's stereotype idiom —
        // `@GetMapping` is itself `@RequestMapping`; a team's `@ApiEndpoint`/`@NightlyJob` wraps a known
        // marker) was NOT rooted by a direct-annotation-only check, orphaning a framework-invoked method
        // from every reachability root (silent-pure for a blast-radius / --agents walk). Resolve the
        // annotation type's own meta-annotations recursively.
        if (annoOrMetaMatches(mn.visibleAnnotations, ROOT_ANNOTATIONS))
            ctx.entryPoints.add(id);
        // CDI observer method: `void onX(@Observes Event e)` is invoked by the CDI container when the
        // event fires, with NO project call site (the @EventListener shape). Unlike the mappings the
        // marker is a PARAMETER annotation, so the method-annotation path above misses it — scan the
        // per-parameter annotation lists. Covers javax/ + jakarta/ enterprise.event.Observes(Async).
        if (anyParamAnnoMatches(mn, PARAM_ROOT_ANNOTATIONS))
            ctx.entryPoints.add(id);
        // gRPC service handler: a project class extends a generated `*ImplBase` and overrides an RPC
        // method whose signature carries an `io.grpc.stub.StreamObserver` — invoked by the gRPC server
        // runtime with no in-project call site. RUNTIME_OVERRIDES can't key on it (the RPC method names
        // are arbitrary) and the generated base isn't on candor's classpath (transSupers can't see
        // `BindableService`), so key on the `*ImplBase` direct super + the StreamObserver-param signature
        // — both gRPC-specific, so no fabrication.
        if (cn.superName != null && cn.superName.toLowerCase(Locale.ROOT).contains("grpc")
                && cn.superName.endsWith("ImplBase")
                && mn.desc.contains("Lio/grpc/stub/StreamObserver;")
                && (mn.access & (Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT)) == 0)
            ctx.entryPoints.add(id);
        // A `finalize()` override is run by the GC's finalizer thread — NOT by any bytecode call.
        // It's the JVM analog of Rust's implicit-Drop hole: an effect (a socket/file opened on
        // collection) that otherwise sits in finalize's own entry but is unreachable from any root,
        // so a "what does this program perform" walk from entry points silently misses it. Unlike
        // Rust we can't attribute it to a drop SITE (finalization is non-deterministic and runs on a
        // detached thread), so the honest model is the runtime-invoked entry point it actually is.
        if (mn.name.equals("finalize") && mn.desc.equals("()V") && (mn.access & Opcodes.ACC_STATIC) == 0)
            ctx.entryPoints.add(id);
        // Serialization callbacks (readObject/writeObject/readExternal/writeExternal/readResolve/
        // writeReplace/readObjectNoData) are invoked REFLECTIVELY by ObjectInput/OutputStream during
        // (de)serialization — no project call site, so an effect (custom read/write doing I/O, a
        // resource opened on resolve, decryption) is orphaned from every reachability root: the
        // finalize shape. Mark them as runtime-invoked entry points, GATED on the class being
        // Serializable/Externalizable so a same-named method on an unrelated class isn't fabricated.
        if ((mn.access & Opcodes.ACC_STATIC) == 0
                && (supers.contains("java/io/Serializable") || supers.contains("java/io/Externalizable"))
                && isSerializationCallback(mn.name, mn.desc))
            ctx.entryPoints.add(id);
        // The program entry `public static void main(String[])` — the JVM invokes it to start the app,
        // the root of a CLI tool's reachability (candor-spec §2, like the Rust impl's `fn main`).
        if (isProgramEntry(mn))
            ctx.entryPoints.add(id);
        // A runtime-invoked override (Runnable/Thread/Callable task body, Spring lifecycle hook,
        // servlet/filter/listener) — invoked by the runtime with NO project call site, so its I/O
        // would otherwise be orphaned from every reachability root (the finalize shape). A null
        // descriptor matches by method name alone (servlet methods carry javax/jakarta param types).
        for (String[] r : runtimeRows)
            if (mn.name.equals(r[1]) && (r[2] == null || mn.desc.equals(r[2]))) {
                ctx.entryPoints.add(id);
                break;
            }
        // The Ktor handler's BODY is `invokeSuspend` (the suspend-lambda's state machine); `invoke` is
        // the bridge that drives it. Mark the body so its effects become a reachability root.
        if (ktorHandler && (mn.name.equals("invokeSuspend") || mn.name.equals("invoke")))
            ctx.entryPoints.add(id);
    }

    /** The AS-EFF-007 taint dataflow frames for one method (null when disabled or unanalyzable). */
    static Frame<TaintValue>[] taintFrames(AnalysisContext ctx, ClassNode cn, MethodNode mn) {
        // AS-EFF-007 taint pass (CANDOR_TAINT): a per-method dataflow whose frames tell us, at each
        // effect call below, whether an argument is parameter-derived. Skipped without the mode, and on
        // bodiless or malformed methods — taint is advisory, so a failed analysis must never crash.
        Frame<TaintValue>[] taintFrames = null;
        if (ctx.taintEnabled && mn.instructions.size() > 0
                && (mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) == 0) {
            try {
                taintFrames = new Analyzer<>(new TaintInterpreter(paramSlots(mn))).analyze(cn.name, mn);
            } catch (Throwable t) { taintFrames = null; }
        }
        return taintFrames;
    }

    /** The receiver-provenance frames for one method (null on bodiless/failed — fail-soft). Reuses the Phase-2
     *  pre-pass's computation for a stream-touching method (consume-once — the main pass reads each once). */
    static Frame<ProvValue>[] provFrames(ClassNode cn, MethodNode mn) {
        Frame<ProvValue>[] pre = ctx().provFramesCache.remove(cn.name + '#' + mn.name + mn.desc);
        return pre != null ? pre : provFramesRaw(cn, mn);
    }

    /** Compute the receiver-provenance frames from scratch (no cache) — the Phase-2 pre-pass memoises via
     *  {@link #cachedProvFrames} so it and the main pass share one computation per stream-touching method. */
    static Frame<ProvValue>[] cachedProvFrames(ClassNode cn, MethodNode mn) {
        String ck = cn.name + '#' + mn.name + mn.desc;
        Frame<ProvValue>[] c = ctx().provFramesCache.get(ck);
        if (c == null) { c = provFramesRaw(cn, mn); if (c != null) ctx().provFramesCache.put(ck, c); }
        return c; // null (bodiless/failed) is cheap to recompute, so it is not cached
    }

    static Frame<ProvValue>[] provFramesRaw(ClassNode cn, MethodNode mn) {
        // Receiver-provenance pass (SOUNDNESS, always-on): tells us at each invokevirtual below whether
        // the receiver is PROVABLY a single `new T`. If so, the dispatch narrows to the one method T
        // resolves — no CHA sibling fan-out (the monomorphic-fabrication fix). Anything else (param,
        // field, return, branch-merged type → genuinely polymorphic) keeps the full CHA over-
        // approximation. Like the taint pass it is fail-soft: a bodiless/native/abstract method, or any
        // analyzer failure, leaves `provFrames` null and the dispatch keeps the CHA exactly as before.
        Frame<ProvValue>[] provFrames = null;
        if (mn.instructions.size() > 0
                && (mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) == 0) {
            try {
                provFrames = new Analyzer<>(new ProvInterpreter()).analyze(cn.name, mn);
            } catch (Throwable t) { provFrames = null; }
        }
        return provFrames;
    }

    /** One MethodInsnNode call site — the engine's core: classification (+ inherited-external-base
     *  re-classification), then the ordered concern units exactly as the original inline block ran
     *  them, then the dispatch edges (static/special exact, virtual/interface via
     *  {@link #virtualDispatch}) and the cross-dep join. ORDER-SENSITIVE: do not reorder the calls. */
    static void handleMethodInsn(AnalysisContext ctx, MethodScan s, MethodInsnNode min) {
        MethodNode mn = s.mn;
        String id = s.id;
        EffectSet dir = s.dir;
        Frame<ProvValue>[] provFrames = s.provFrames;
        String owner = min.owner.replace('/', '.');
        Effect effect = Classifier.classify(owner, min.name, min.desc);
        // A project class that SUBCLASSES a classify-modeled external effectful type (extends a
        // Testcontainers GenericContainer, a java.io stream, …) and calls an INHERITED method:
        // classify sees the PROJECT owner (no rule) and the real body lives in the external base
        // (unscanned) → silent-pure. Re-run classify against the external supertype the JVM
        // dispatches to. Gated: only when the project owner has NO concrete body of its own for the
        // method (not overridden — else that analysed body wins) and no PROJECT super provides one.
        // Orthogonal to the persistence registries (which cover bases classify does NOT model).
        if (effect == null && ctx.byName.containsKey(min.owner)
                && !declaresConcrete(ctx.byName.get(min.owner), min.name, min.desc)
                && nearestConcreteSuper(min.owner, min.name, min.desc) == null) {
            for (String sup : transSupers(min.owner)) {
                if (ctx.byName.containsKey(sup)) continue;   // external supers only
                Effect se = Classifier.classify(sup.replace('/', '.'), min.name, min.desc);
                // UNION every matching external super, not first-wins: transSupers is a HashSet, so
                // a `break` made the chosen effect order-dependent (nondeterministic) when two
                // modeled supers declare the same method with different effects. dir is a set →
                // union is deterministic + sound (it's the over-approx of the possible dispatches).
                if (se != null) { dir.add(se); effect = se; }
            }
        }
        if (effect != null) dir.add(effect);
        // SPEC §1 ⟨0.13⟩ `Llm` model-SDK surface (Rules.MODEL_SDK_PACKAGES): a call into a curated
        // model-provider client dispatches a request → Llm + Net (Net is never dropped — a model call IS
        // network I/O). Set `effect` to LLM so the injection-taint surface (a caller-derived prompt) fires,
        // exactly as it does for a Net/Db arg. Additive to whatever classify already found.
        // Two carve-outs keep the blanket SOUND (it stays the default → no genuine dispatch is ever missed)
        // while killing the builder/ctor fabrication:
        //  - a CONSTRUCTOR (`<init>`) only builds the client (config + a lazy HTTP/Retrofit stub) and
        //    dispatches no request (true for every curated SDK — all lazy clients), so it stays pure;
        //  - a Spring AI ChatClient FLUENT-BUILDER step (prompt/user/system/…) assembles a request but
        //    touches no wire. A DENYLIST (only proven-pure methods carved out) — anything else, including
        //    every real dispatch (call/stream/content/embed/… and any provider method we haven't enumerated)
        //    stays Llm+Net. A forgotten builder over-reports (safe); nothing is ever silently dropped.
        if (isModelSdkOwner(owner) && !min.name.equals("<init>")
                && !Rules.isSpringAiPureBuilder(owner, min.name)) {
            dir.add(Effect.LLM);
            dir.add(Effect.NET);
            if (effect == null) effect = Effect.LLM;
        }
        opaqueTaskHandoff(ctx, s, min, owner);
        namedFunctionalToHof(ctx, s, min);
        xmlParseFilePrecision(s, min);
        entryAbstractStream(ctx, s, min, owner, effect);
        externalStreamUtility(ctx, s, min, owner, effect);
        contractReentry(s, min);
        deferredForce(ctx, s, min);
        reflectionPair(ctx, s, min, owner);
        kappaLedger(ctx, s, min, owner, effect);
        effectMetadata(ctx, s, min, owner, effect);
        extractLiteralSurfaces(ctx, s, min, owner, effect);
        boolean springTyped = declarativeIoRules(ctx, s, min);

        int op = min.getOpcode();
        // A static call triggers the owner's class-load → its `<clinit>` runs.
        if (op == Opcodes.INVOKESTATIC) clinitEdge(id, min.owner);
        if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKEINTERFACE) {
            // mono-receiver resolved locally → the original `continue`: skip cross-dep too.
            if (virtualDispatch(ctx, s, min, owner, effect, springTyped)) return;
        } else if (ctx.projectClasses.contains(min.owner)) {
            // static / special (super, private, ctor) — the descriptor is known, so an overloaded callee
            // resolves to the right overload. But a SUPER-call (or static call) to an INHERITED method names
            // the DIRECT superclass in `min.owner`, which may NOT declare the method — it is inherited from
            // higher up, e.g. through a generic intermediate class (`Poolable extends Delegating<C> extends
            // Trace`, `super.setLastUsed()` compiling to INVOKESPECIAL owner=Delegating). Edging to
            // `owner.method` then dangles on a non-existent node and the callee's effect is silently lost —
            // found on commons-dbcp2 (`PoolableConnection.setLastUsed → super.setLastUsed() → Instant.now()`,
            // reported pure; the runtime oracle caught the escaped Clock). Resolve to the nearest superclass
            // that actually DECLARES the method, exactly as the virtual path does; fall back to the raw owner
            // when it declares the method itself or the target is unresolvable (external / not loaded).
            String special = declaresConcrete(ctx.byName.get(min.owner), min.name, min.desc)
                    ? methodId(owner, min.name, min.desc)
                    : nearestConcreteSuper(min.owner, min.name, min.desc);
            ctx.edges.get(id).add(special != null ? special : methodId(owner, min.name, min.desc));
            // PRIVATE FUNCTIONAL-PARAM FORWARDING (collect): record the lambda this site passes
            // to a private functional-param sink (or mark it opaque) — resolved in runScan.
            collectForwardingArg(owner, min, provFrames == null ? null : provFrames[mn.instructions.indexOf(min)]);
        }
        crossDepJoin(ctx, s, min, effect, springTyped);
    }

    /** Executor hand-off: an OPAQUE task (field/param/factory return) submitted to an executor runs
     *  outside project code → Unknown, never silent-pure. */
    static void opaqueTaskHandoff(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner) {
        MethodNode mn = s.mn;
        String id = s.id;
        EffectSet dir = s.dir;
        Frame<ProvValue>[] provFrames = s.provFrames;
        // Executor hand-off: `es.submit(task)`/`execute`/`schedule*` and `new Thread(task)` invoke
        // the task's run()/call() OUTSIDE project code. A fresh `new R()` (the NEW-site edge
        // attributes R.run) or an inline lambda (edged at its indy) is already captured; an OPAQUE
        // task — a field, a param, a factory return — has an unknown body, so the handing-off
        // method must read Unknown (parallel to an unpinned `task.run()`), else it is silent-pure.
        if ((isExecutorHandoff(min.owner, min.name, min.desc)
                || isSyncCallbackInvoker(min.owner, min.name, min.desc)) && provFrames != null) {
            ProvValue task = handoffTaskArg(provFrames[mn.instructions.indexOf(min)], min);
            if (task != null && !task.fromIndy && task.newType == null) {
                dir.add(Effect.UNKNOWN);
                ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                        .add(UnknownReason.of(UnknownReason.Kind.TASK_HANDOFF, owner + "." + min.name));
            }
        }
    }

    /** A freshly-constructed NAMED functional-interface instance handed to a known-INVOKING library
     *  HOF: edge its SAM surface (the lambda-parity fix, allowlist-gated). */
    static void namedFunctionalToHof(AnalysisContext ctx, MethodScan s, MethodInsnNode min) {
        MethodNode mn = s.mn;
        String id = s.id;
        Frame<ProvValue>[] provFrames = s.provFrames;
        // NAMED FUNCTIONAL-INTERFACE INSTANCE handed to a known-INVOKING library HOF. A
        // `new EffCons()` (a project class implementing java.util.function.*/Comparator/FileFilter)
        // passed to a library method that INVOKES its SAM outside project code (`Stream.forEach`,
        // `List.sort`, `File.listFiles`) reads SILENT-PURE: there is no invokedynamic (so the
        // lambda creation-edge never fires) and no in-project SAM invoke (the `.accept()` is inside
        // the unanalysed JDK body). A lambda/method-ref in the SAME position IS sound (edged at its
        // indy), so this was an INTERNAL asymmetry. Edge the instance's SAM surface here — GATED on
        // an explicit ALLOWLIST of known-INVOKING HOF method names (isInvokingHof). The earlier
        // `!isStoringContainerCall` gate was UNSOUND (a code review found it FABRICATED: it fired
        // for ANY external non-store, so `Objects.requireNonNull(c)` / `Optional.ofNullable(c)` /
        // `map.getOrDefault(k,c)` / `Stream.of(c)` / `new TreeMap<>(cmp)` — which merely RECEIVE
        // or STORE the instance, never invoke it — edged the SAM = a phantom effect). The allowlist
        // never fabricates on a non-invoking sink; a genuinely-invoking HOF not on the list is a
        // sound UNDER-report (no edge), never a fabrication. Restricted to a freshly-constructed
        // (`newType`) project functional impl and EXTERNAL callees (a project callee's body is
        // analysed directly).
        if (provFrames != null && !ctx.projectClasses.contains(min.owner)
                && isInvokingHof(min.name)) {
            for (ProvValue a : callArgs(provFrames[mn.instructions.indexOf(min)], min)) {
                if (a == null || a.newType == null) continue;
                ctx.edges.get(id).addAll(functionalSamSurface(a.newType));
            }
        }
    }

    /** XML parse(File) precision: the File overload definitely reads the file — add Fs beside the
     *  XXE Unknown classify() already yields. */
    static void xmlParseFilePrecision(MethodScan s, MethodInsnNode min) {
        EffectSet dir = s.dir;
        // XML parse(File) PRECISION: the parser's `parse` already classifies as the XXE/external-
        // entity Unknown (security disclosure, see classify ~4367). The File overload ALSO
        // DEFINITELY reads the file — add Fs here so the effect set is the precise {Fs, Unknown}
        // (reads this file for sure; may resolve external entities). The InputStream/InputSource
        // overloads (caller stream) and the (String systemId) overload (path-vs-URL ambiguous)
        // get no Fs. Added in the call handler because classify()'s single slot is the Unknown.
        if ((min.owner.equals("javax/xml/parsers/DocumentBuilder")
                || min.owner.equals("javax/xml/parsers/SAXParser"))
                && min.name.equals("parse") && min.desc.startsWith("(Ljava/io/File;")) dir.add(Effect.FS);
    }

    /** R17: a rooted entry point reading an externally-provided ABSTRACT java.io stream — real I/O of
     *  unknown kind → Unknown (SOUNDNESS.md R17). */
    static void entryAbstractStream(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner, Effect effect) {
        MethodNode mn = s.mn;
        String id = s.id;
        EffectSet dir = s.dir;
        Frame<ProvValue>[] provFrames = s.provFrames;
        boolean isEntry = s.isEntry;
        // R17 — a rooted ENTRY POINT reading an externally-provided ABSTRACT java.io stream: the
        // receiver is the entry point's OWN parameter (framework-injected), its concrete impl is
        // unresolvable, and the read/write on the abstract base classifies pure. The I/O is real
        // but of unknown kind (Fs/Net per the concrete) → disclose Unknown, not silent-pure.
        // Gated to entry points so an internal helper reading a PASSED stream — whose in-project
        // caller HAS the concrete (effect already attributed at the creation site) — doesn't
        // flood. SOUNDNESS.md R17 (the abstract-java.io-stream boundary).
        if (effect == null && isEntry && provFrames != null && isAbstractStreamIo(min.owner, min.name)) {
            ProvValue recv = receiverProv(provFrames[mn.instructions.indexOf(min)], min);
            if (isOwnParam(mn, recv, provFrames[0])) {
                dir.add(Effect.UNKNOWN);
                ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                        .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, owner + "." + min.name));
            }
        }
    }

    /** VALUE-PROVENANCE Phase 1 (interprocedural stream provenance, the intraprocedural half). A stream-
     *  CONSUMING library utility (`IOUtils.read`/`copy`/`toByteArray`, Guava `ByteStreams`/`CharStreams`)
     *  reads the InputStream/Reader passed to it. candor's source/sink stance classifies these pure-relative —
     *  the effect is charged at the stream's CREATION — which is sound when the stream was opened IN THIS
     *  method (a fresh `new FileInputStream(...)`: newType is set, so this method already carries the Fs). But
     *  when the argument is a PARAM or a FIELD (newType == null — opened OUTSIDE this method, e.g.
     *  `ZipArchiveInputStream.readFully → IOUtils.read(this.in,…)`), the read is of an externally-provided
     *  stream whose concrete type — and effect — candor cannot see → Unknown, never silent-pure and never a
     *  fabricated Fs. This is R17's `entryAbstractStream` generalised from "an entry point's own param" to
     *  "any stream not opened in this method", applied at the utility-consumer call site (where the stream is
     *  an ARGUMENT, not the receiver). Whole-program precision — a caller's concrete stream flowing into the
     *  field, so `readFully` resolves to Fs rather than Unknown — is reclaimed by the construction-carried
     *  binding (Phase 2). See VALUE-PROVENANCE-DESIGN.md. Note it fires at the CALL SITE, not in classify(),
     *  so the pure-relative stance table (ClassifierLongTailTest.commonsIoFollowsTheSourceSinkStance) stands. */
    static void externalStreamUtility(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner, Effect effect) {
        if (effect != null) return;                     // a File/URL overload already classified Fs/Net — leave it
        Frame<ProvValue>[] provFrames = s.provFrames;
        if (provFrames == null) return;
        Set<String> verbs = Rules.STREAM_CONSUMING_UTILITIES.get(min.owner);
        if (verbs == null || !verbs.contains(min.name)) return;
        Frame<ProvValue> f = provFrames[s.mn.instructions.indexOf(min)];
        if (f == null) return;
        Type[] at = Type.getArgumentTypes(min.desc);
        // Check EVERY InputStream/Reader argument — a dual-input verb (IOUtils.contentEquals(in,in) /
        // (reader,reader)) reads BOTH, so a fresh first arg must not mask an external second one.
        for (int i = 0; i < at.length; i++) {
            if (at[i].getSort() != Type.OBJECT) continue;
            String tn = at[i].getInternalName();
            if (!tn.equals("java/io/InputStream") && !tn.equals("java/io/Reader")) continue;
            ProvValue a = callArg(f, min, i);
            // newType != null ⇒ a fresh in-scope `new` ⇒ opened in THIS method ⇒ pure-relative — skip.
            if (a == null || a.newType != null) continue;
            // Phase 2: a FIELD proven (whole-program) bound only to in-scope concrete opens is pure-relative to
            // a VISIBLE open (the effect is charged at that open) — skip it and keep checking the other args.
            if (a.fieldOrigin != null && ctx.suppressibleStreamFields.contains(a.fieldOrigin)) continue;
            // An external/unknown-origin stream argument: disclose Unknown, once, and stop.
            s.dir.add(Effect.UNKNOWN);
            ctx.unknownWhy.computeIfAbsent(s.id, k -> new TreeSet<>())
                    .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, owner + "." + min.name));
            return;
        }
    }

    /** VALUE-PROVENANCE Phase 2 pre-pass. Computes the set of instance stream fields ("owner#name") PROVEN
     *  bound only to in-scope concrete opens across the WHOLE program, so a consuming read of one is
     *  pure-relative and its Phase-1 Unknown is suppressed. CONSERVATIVE by construction — a field enters the
     *  set only when every binding is provably concrete; any doubt (a foreign source, a filter-wrap, an
     *  unresolved construction site, a param-sourced field of a subclassed class) leaves it out, keeping the
     *  sound Phase-1 disclosure. A wrongly-suppressed Unknown would be a silent under-report, so the whole
     *  pass errs to NOT suppressing. See VALUE-PROVENANCE-DESIGN.md. */
    static void computeStreamFieldOrigins(List<ClassNode> classes) {
        AnalysisContext ctx = ctx();
        // A param-sourced field of a class with a PROJECT subclass can be bound via super() from a `new
        // Subclass(...)` we would have to trace through — reject those to stay sound+simple.
        Set<String> subclassed = new HashSet<>();
        for (ClassNode cn : classes)
            if (cn.superName != null && ctx.byName.containsKey(cn.superName)) subclassed.add(cn.superName);

        Map<String, Set<Integer>> fieldParams = new HashMap<>(); // owner#name -> ctor param indices flowing in
        Set<String> concreteSelf = new HashSet<>();              // owner#name -> has a `this.F = new SelfSource()` binding
        Set<String> rejected = new HashSet<>();                  // owner#name -> proven NOT suppressible
        Set<String> candidates = new HashSet<>();                // owner#name stream fields with >=1 PUTFIELD

        // The GLOBAL set of instance stream fields ("owner#name") declared anywhere in the project. A field is
        // keyed by its DECLARING class, and a PUTFIELD to it can appear in ANY class (a package-private/
        // protected/public field rebound cross-class, or a nestmate write to a private field) — so Step 1 must
        // scan every method of every class against this global set, not just each class's own fields, or an
        // external rebinding elsewhere would go unseen and wrongly leave the field suppressible.
        Set<String> streamFieldKeys = new HashSet<>();
        for (ClassNode cn : classes) {
            if (cn.fields == null) continue;
            for (FieldNode fn : cn.fields)
                if ((fn.access & Opcodes.ACC_STATIC) == 0 && isStreamFieldDesc(fn.desc))
                    streamFieldKeys.add(cn.name + "#" + fn.name);
        }
        if (streamFieldKeys.isEmpty()) return;

        // Step 1 — classify EVERY PUTFIELD (in any class) that stores an instance stream field.
        for (ClassNode cn : classes) {
            for (MethodNode mn : cn.methods) {
                Frame<ProvValue>[] pf = null; // computed lazily, only for methods that store one of these fields
                AbstractInsnNode[] insns = mn.instructions.toArray();
                for (int i = 0; i < insns.length; i++) {
                    if (!(insns[i] instanceof FieldInsnNode fi) || fi.getOpcode() != Opcodes.PUTFIELD) continue;
                    String key = fi.owner + "#" + fi.name;
                    if (!streamFieldKeys.contains(key)) continue;
                    candidates.add(key);
                    if (pf == null) pf = cachedProvFrames(cn, mn);
                    ProvValue v = (pf != null && pf[i] != null && pf[i].getStackSize() > 0)
                            ? pf[i].getStack(pf[i].getStackSize() - 1) : null;
                    if (v == null) { rejected.add(key); continue; }
                    if (v.newType != null && Rules.SELF_SOURCING_STREAMS.contains(v.newType)) { concreteSelf.add(key); continue; }
                    if (v.fieldOrigin != null && v.fieldOrigin.equals(key)) continue; // self-rewrap (this.F = f(this.F)) — no new binding
                    // A ctor-PARAM binding is only trustworthy in the field's DECLARING class's own <init> (that
                    // param maps to `new C(args)` construction sites, resolved in Step 2). A param/local bound in
                    // any OTHER method — a cross-class write, a setter, a non-declaring-class <init> — is an
                    // external rebinding we cannot prove concrete → reject.
                    boolean inDeclaringCtor = mn.name.equals("<init>") && fi.owner.equals(cn.name);
                    int idx = inDeclaringCtor ? paramIndexOf(mn, v, pf[0]) : -1;
                    if (idx >= 0) { fieldParams.computeIfAbsent(key, k -> new HashSet<>()).add(idx); continue; }
                    rejected.add(key); // foreign field, method return, filter-wrap, cross-class/non-ctor param — cannot prove concrete
                }
            }
        }

        // Step 2 — a param-sourced field needs EVERY `new C(args)` site to pass a self-sourcing concrete for
        // each of its param slots (and >=1 site). Reject those of a subclassed class outright.
        Set<String> paramFields = new HashSet<>(fieldParams.keySet());
        paramFields.removeAll(rejected);
        for (String key : new HashSet<>(paramFields))
            if (subclassed.contains(key.substring(0, key.indexOf('#')))) { rejected.add(key); paramFields.remove(key); }
        Set<String> paramHasSite = new HashSet<>();
        if (!paramFields.isEmpty()) {
            for (ClassNode cn : classes) {
                for (MethodNode mn : cn.methods) {
                    Frame<ProvValue>[] pf = null;
                    AbstractInsnNode[] insns = mn.instructions.toArray();
                    for (int i = 0; i < insns.length; i++) {
                        if (!(insns[i] instanceof MethodInsnNode mi) || mi.getOpcode() != Opcodes.INVOKESPECIAL
                                || !mi.name.equals("<init>")) continue;
                        boolean relevant = false;
                        for (String key : paramFields) if (key.startsWith(mi.owner + "#")) { relevant = true; break; }
                        if (!relevant) continue;
                        if (pf == null) pf = cachedProvFrames(cn, mn);
                        for (String key : paramFields) {
                            if (!key.startsWith(mi.owner + "#")) continue;
                            paramHasSite.add(key);
                            if (pf == null || pf[i] == null) { rejected.add(key); continue; }
                            for (int idx : fieldParams.get(key)) {
                                ProvValue arg = argAt(pf[i], mi, idx);
                                if (arg == null || arg.newType == null || !Rules.SELF_SOURCING_STREAMS.contains(arg.newType))
                                    rejected.add(key); // an external / non-self-sourcing construction arg — cannot suppress
                            }
                        }
                    }
                }
            }
        }
        // a param-sourced field with NO in-scope construction site is library-view (constructed by callers we
        // cannot see) → external → keep the Phase-1 disclosure.
        for (String key : fieldParams.keySet()) if (!paramHasSite.contains(key)) rejected.add(key);

        // Step 3 — a field is suppressible iff it has >=1 proven-concrete binding and NO rejected binding.
        for (String key : candidates) {
            if (rejected.contains(key)) continue;
            if (concreteSelf.contains(key) || (fieldParams.containsKey(key) && paramHasSite.contains(key)))
                ctx.suppressibleStreamFields.add(key);
        }
    }

    /** An instance field whose declared type is an abstract java.io stream base — the fields the value-
     *  provenance summary reasons about (a concrete-typed field carries its own effect already). */
    static boolean isStreamFieldDesc(String desc) {
        return desc.equals("Ljava/io/InputStream;") || desc.equals("Ljava/io/OutputStream;")
                || desc.equals("Ljava/io/Reader;") || desc.equals("Ljava/io/Writer;");
    }

    /** The declared-parameter index (excluding the receiver) that value {@code v} IS, or -1 if it is not one
     *  of {@code mn}'s own parameters. {@code f0} is the entry frame ({@code provFrames[0]}). */
    static int paramIndexOf(MethodNode mn, ProvValue v, Frame<ProvValue> f0) {
        if (v == null || f0 == null) return -1;
        int n = Type.getArgumentTypes(mn.desc).length;
        for (int i = 0; i < n; i++) if (isParamValue(mn, v, f0, i)) return i;
        return -1;
    }

    /** Implicit-contract reentry: JDK sinks that re-enter user code via toString/equals/hashCode/
     *  compareTo, plus the writer-side formatting facades (R16). */
    static void contractReentry(MethodScan s, MethodInsnNode min) {
        MethodNode mn = s.mn;
        String id = s.id;
        Frame<ProvValue>[] provFrames = s.provFrames;
        // IMPLICIT-CONTRACT-REENTRY: a JDK sink that re-enters user code via the JVM contract
        // (toString/equals/hashCode/compareTo) — modelled pure by candor, so an EFFECTFUL override
        // of the argument's type read silent-pure. CHA the contract method over the ARGUMENT's
        // DECLARED type and edge to its LOCAL override(s); an external/Object-default/pure override
        // yields no local body (or no effect) → contributes nothing (no flood, no fabrication).
        if (provFrames != null) {
            Frame<ProvValue> rf = provFrames[mn.instructions.indexOf(min)];
            if (isToStringSink(min.owner, min.name, min.desc)) {
                if (min.owner.equals("java/lang/String") && min.name.equals("format")) {
                    // format(...) packs `%s` operands into an Object[] varargs — the element types
                    // are erased on the stack, so resolve them from the array-fill AASTOREs.
                    reentryFormatVarargs(id, mn, min, provFrames);
                } else {
                    // valueOf/Objects.toString/append(Object)/print(Object): the lone Object arg.
                    for (ProvValue a : callArgs(rf, min)) reentryEdge(id, a, C_TOSTRING);
                }
            }
            if (isEqualsHashSink(min.owner, min.name)) {
                // The KEY/element argument — for Map.* it is the FIRST arg (the key); for the
                // collection verbs it is the lone element arg. Reenter both equals AND hashCode.
                ProvValue key = callArg(rf, min, 0);
                reentryEdge(id, key, C_EQUALS);
                reentryEdge(id, key, C_HASHCODE);
            }
            if (isCompareToSink(min.owner, min.name)) {
                // The element whose compareTo orders the collection. For the COLLECTION-typed sinks
                // (Collections.sort(List)/list.sort/Arrays.sort(Object[])/TreeSet.add) the element
                // type is hidden inside the container generic (erased) — NOT recoverable from the
                // declType of the List/array argument. So we resolve over the ARGUMENT's declType
                // when it is itself the compared element (TreeSet.add(E)/TreeSet.contains/
                // TreeMap.get/put/containsKey take the element/key DIRECTLY). For sort over a
                // container we cannot see the element type — left as an honest residual (the
                // container's element override is still attributed at any explicit compareTo call,
                // and a `new TreeSet().add(localComparable)` IS caught here via the direct arg).
                ProvValue elem = callArg(rf, min, 0);
                reentryEdge(id, elem, C_COMPARETO);
            }
            // WRITER side (R16): constructing a JDK formatting facade over a CUSTOM sink drives
            // the sink's append/write when it formats. `new Formatter(Appendable)` → append;
            // `new PrintWriter(Writer|OutputStream)` / `new PrintStream(OutputStream)` → write.
            // The sink's method is reached only THROUGH the non-local facade, so otherwise it was
            // silent — the write-fmt writer-side blind spot (cf. the rust/swift engines). The sink
            // is the ctor's first arg; resolve-or-skip over its declType (a std StringBuilder /
            // FileOutputStream has no LOCAL append/write override → contributes nothing).
            String sinkContract = formatterSinkCtor(min.owner, min.name, min.desc);
            if (sinkContract != null) reentryEdge(id, callArg(rf, min, 0), sinkContract);
            // R32 — a DIRECT call to a concrete PROVIDED java.io method (`w.write(String)` / `w.append(..)` /
            // `r.read(char[])`) whose JDK body drives the abstract required method on the RECEIVER. The
            // receiver's own abstract override is reached only THROUGH the non-local provided overload, so
            // otherwise it was silent (the direct sibling of the facade case above, which drives the ARG).
            // Gated on the RECEIVER's type being a java.io stream (so a coincidental project `write`/`read`
            // never triggers) then resolve-or-skip over its declType — a std FileWriter /
            // ByteArrayOutputStream has no LOCAL write/read override → contributes nothing.
            String recvContract = ioDriverContract(min.name);
            if (recvContract != null) {
                ProvValue recv = receiverProv(rf, min);
                if (recv != null && isJavaIoStreamType(recv.declType)) reentryEdge(id, recv, recvContract);
            }
        }
    }

    /** True-forwarding force site: a container-forcing call on a tracked deferred field binds a
     *  deferred edge, resolved after all classes are analyzed. */
    static void deferredForce(AnalysisContext ctx, MethodScan s, MethodInsnNode min) {
        MethodNode mn = s.mn;
        String id = s.id;
        // TRUE-FORWARDING force site: a known container-forcing call (`Lazy.getValue` /
        // `ThreadLocal.get`) on a receiver that is a GET* of a tracked deferred field — possibly
        // a field of ANOTHER class (`t.tl.get()`). Bind, per the SPECIFIC field, a deferred edge
        // resolved after all classes are analysed (the binding side may be in any class). The
        // receiver is the GET* immediately producing the container value; we require its field
        // descriptor to be a container type so an unrelated `.get()` never matches.
        if (isDeferredForce(min.owner, min.name)) {
            String fieldKey = forcedFieldKey(mn, min);
            if (fieldKey != null) ctx.deferredForcePairs.add(new String[] { id, fieldKey });
        }
    }

    /** Reflection pair capture: Class.getMethod/getDeclaredMethod with a literal name (+ receiver
     *  class) — the edge forms in resolution only against a project receiver. */
    static void reflectionPair(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner) {
        MethodNode mn = s.mn;
        String id = s.id;
        if (owner.equals("java.lang.Class")
                && (min.name.equals("getMethod") || min.name.equals("getDeclaredMethod"))) {
            // Capture the literal method NAME (nearest String, not an unrelated earlier
            // constant) AND the RECEIVER class (the `X.class` literal). The edge is only
            // formed in resolution when the receiver is a project class — never a global
            // leaf-name match that fabricates an edge to an unrelated same-named method.
            String lit = nearestLiteralArg(mn, min);
            String recv = reflectReceiver(mn, min);
            if (lit != null) ctx.reflectPairs.add(new String[] { id, lit, recv == null ? "" : recv });
        }
    }

    /** The κ-coverage ledger (external packages seen/classified/blind) + the structural Spring
     *  κ-floor (unmodeled Spring I/O-convention member → disclosed Unknown, not silently dropped). */
    static void kappaLedger(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner, Effect effect) {
        String id = s.id;
        EffectSet dir = s.dir;
        // κ ledger: key external owners by their EXACT package (the slash-form owner
        // up to the class segment — no uppercase heuristic, which mangled lowercase/
        // obfuscated classes); array owners ([Ljava/lang/String; — every enum's
        // values() clone) are types, not packages, and stay out. A package with zero
        // classifications anywhere in the scan is a named blind spot.
        if (!ctx.projectClasses.contains(min.owner) && min.owner.charAt(0) != '[') {
            int slash = min.owner.lastIndexOf('/');
            String pkg = slash > 0 ? min.owner.substring(0, slash).replace('/', '.') : "";
            if (!pkg.isEmpty() && !kappaCovers(pkg)) {
                ctx.kappaSeen.merge(pkg, 1, Integer::sum);
                if (effect != null) ctx.kappaClassified.add(pkg);
                // A FLOORED call (classifier returned pure) into an external package is a candidate
                // per-method blind spot. Post-filtered to packages κ never classified ANYWHERE
                // (so a known package's pure method isn't disclosed) and propagated to callers.
                else ctx.blindDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(pkg);
            } else if (!pkg.isEmpty() && effect == null
                    && pkg.startsWith("org.springframework")
                    && isSpringIoOwner(min.owner) && !isConventionallyPure(min.name)) {
                // STRUCTURAL SPRING-FLOOR FIX: org.springframework.* is a κ-covered prefix, so an
                // UNMODELED Spring sub-library leaf would otherwise be SILENTLY DROPPED (worse than
                // a disclosed Unknown — the floor exists so pure Spring utils like StringUtils aren't
                // disclosed blind). But an unmodeled member of a Spring I/O-CONVENTION type
                // (*Template/*Operations/*Repository/*Gateway — Spring's "this class does I/O"
                // naming) is very likely a real effect candor just hasn't modeled (Spring Integration
                // MessagingTemplate, Spring Batch, the next Spring sub-project…). Disclose Unknown
                // (the SAFE direction — never a fabricated concrete effect) instead of dropping it.
                // The modeled Spring templates' I/O methods return effect!=null so never reach here;
                // only a genuinely-unmodeled member (or a rare pure accessor → harmless Unknown) does.
                dir.add(Effect.UNKNOWN);
                ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                        .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, owner + "." + min.name));
            }
        }
    }

    /** Per-effect metadata for a classified call: the AS-EFF-007 taint surface, the reflect
     *  unknownWhy, and the Fs read/write kind refinement. */
    static void effectMetadata(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner, Effect effect) {
        MethodNode mn = s.mn;
        String id = s.id;
        Frame<TaintValue>[] taintFrames = s.taintFrames;
        // An injection-class effect on a caller-derived argument is an injection surface.
        if (taintFrames != null && effect != null && INJECTION.contains(effect)
                && argsTainted(taintFrames[mn.instructions.indexOf(min)], min))
            ctx.tainted.computeIfAbsent(id, k -> EffectSet.empty()).add(effect);
        if (effect == Effect.UNKNOWN) // reflection / dynamic invoke (classify §)
            ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                    .add(UnknownReason.of(UnknownReason.Kind.REFLECT, owner + "." + min.name));
        if (effect == Effect.FS) { // non-breaking read/write refinement of Fs
            List<String> k = fsKind(owner, min.name);
            if (!k.isEmpty()) ctx.fsDirect.computeIfAbsent(id, x -> new TreeSet<>()).addAll(k);
        }
    }

    /** The AS-EFF-008 literal surfaces (SPEC §2 `cmds`/`paths`/`hosts`/`tables`), grouped: the Exec
     *  program head, the Fs path, the Net host (bare `(String,int)` ctors + the per-call literal
     *  window + the URL-terminal attribution) and the Db tables — each with its fail-closed
     *  surface-incompleteness (masking) guard. `capturedHostHere` feeds the Net completeness check,
     *  which is why the four surfaces live in ONE unit. */
    static void extractLiteralSurfaces(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner, Effect effect) {
        MethodNode mn = s.mn;
        String id = s.id;
        EffectSet dir = s.dir;
        Map<Integer, String> constLocals = s.constLocals;
        Map<Integer, String> urlLocals = s.urlLocals;
        // AS-EFF-008 literal surfaces (SPEC §2 `cmds`/`paths`): the subprocess program and the
        // file path, read from the FIRST string-literal arg of the call that carries it — the
        // ProcessBuilder/Runtime.exec command, the Path.of / File / file-stream ctor path.
        if ((owner.equals("java.lang.ProcessBuilder") && min.name.equals("<init>"))
                || (owner.equals("java.lang.Runtime") && min.name.equals("exec"))) {
            // Only the program HEAD (argv[0]) names the command — a later argument is DATA
            // (§4; mirrors candor-rust's is_cmd_naming_method). `programHeadLiteral` reads
            // argv[0] specifically; the loose `firstLiteralArg` would grab a trailing literal
            // (`new ProcessBuilder(toolVar, "curl")` → "curl"), fabricating a `cmds` head and
            // letting `allow Exec curl` spuriously pass on a DYNAMIC head. Both the literal
            // capture AND the cliff refinement (spec §4 ⟨0.5⟩: `curl`→Net, `candor`→Fs/Env)
            // therefore key off argv[0]; a dynamic head keeps the bare Exec cliff with no
            // `cmds`. Exec itself is emitted unconditionally below — only the literal tightens.
            String head = programHeadLiteral(min);
            if (head != null) {
                ctx.cmdsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(head);
                dir.addAll(EffectSet.ofNames(commandHeadEffects(head)));
            } else {
                // a program-NAMING Exec call with a RUNTIME head (no literal) — the command is
                // invisible to the gate, so a benign sibling literal must not mask it (sweep [0],
                // the masking guard generalized from Net to Exec/Fs/Db).
                ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Exec");
            }
        }
        // …only the overload whose path is a SINGLE leading String arg (descriptor
        // `(Ljava/lang/String;)` or `(Ljava/lang/String;[…` for Path.of's varargs). A
        // two-String ctor — `RandomAccessFile(String,String)`, `File(String,String)` — can
        // have a NON-path literal as its only constant (a `"r"`/`"rw"` mode, a child name)
        // when the path itself is runtime-computed, which firstLiteralArg would then grab.
        if (((owner.equals("java.nio.file.Path") && min.name.equals("of"))
                || (owner.equals("java.nio.file.Paths") && min.name.equals("get"))
                || (PATH_CTOR_OWNERS.contains(owner) && min.name.equals("<init>")))
                && pathArgIsSingleString(min.desc)) {
            String p = firstLiteralArg(mn, min);
            if (p != null) ctx.pathsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(p);
            // a path-establishing call with a RUNTIME path (single-String arg, no literal) — the
            // path is invisible to the gate (masking guard generalized to Fs, sweep [0]).
            else ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Fs");
        }
        // A bare-hostname Net endpoint: `new Socket("api.stripe.com", 443)` /
        // `new InetSocketAddress("api.stripe.com", 443)` names the host as a STRING argv[0]
        // with a numeric port — but as a bare hostname (no scheme/`:port`) netHostLiteral
        // rejects it (deliberately, to avoid the ~14 false dotted "hosts" a loose filter
        // produced). Here the CALL SITE disambiguates: a `(String host, int port)` ctor's
        // first String literal IS a host, so extract it without loosening netHostLiteral.
        // Gated to the `(Ljava/lang/String;I…` shape, so the `(InetAddress,int)` and
        // `(String,int,InetAddress,int)`-with-computed-host overloads add nothing.
        boolean capturedHostHere = false;
        if ((owner.equals("java.net.Socket") || owner.equals("java.net.InetSocketAddress")
                // java.util.logging.SocketHandler(String host, int port) opens a log socket to that
                // host — same `(String,int)` shape. Its host must reach the AS-EFF-008 surface, else
                // a forbidden exfil host (e.g. evil.exfil.com) is invisible and a benign co-located
                // Net literal MASKS it (the 0.5.27 SocketHandler Net rule without surfacing → a gate
                // EVASION found by a security sweep).
                || owner.equals("java.util.logging.SocketHandler"))
                && min.name.equals("<init>") && min.desc.startsWith("(Ljava/lang/String;I")) {
            String h = firstLiteralArg(mn, min);
            // The host must look like a host (a dotted name / IPv4), not e.g. a "localhost"
            // bareword that could equally be anything — reuse hostPart's shape via a dot test,
            // matching netHostLiteral's "contains a dot" gate for bare host:port.
            if (h != null && h.contains(".") && !h.contains("/") && !h.contains(" ")) {
                // Append the literal int port for `host:port` (SPEC §2) — so a two-arg
                // Socket("h", 443) matches the URL form's `h:port` and candor-scan, instead of
                // dropping the statically-known port (adversarial coverage-gap review, GAP2).
                String port = intLiteralBefore(min);
                String hostLit = port != null ? h + ":" + port : h;
                ctx.hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(hostLit);
                dir.addAll(EffectSet.ofNames(modelHostEffects(hostLit))); // §1 ⟨0.13⟩ Llm host-literal refinement
                capturedHostHere = true;
            } else if (h != null && !h.contains("/") && !h.contains(" ")) {
                // §1 ⟨0.13⟩ Ollama: a LOCAL model endpoint names a bare host (`localhost`/`127.0.0.1`)
                // that the dotted-host gate above rejects — the model signal is the `:11434` PORT. Refine
                // to Llm on that port WITHOUT capturing the host as a Net literal (the dotless-host gate
                // stays intact; this only adds the effect).
                String port = intLiteralBefore(min);
                if ("11434".equals(port)) dir.add(Effect.LLM);
            }
        }
        // Host literal from THIS host-bearing call's OWN argument (a URL/URI string, a Spring/
        // ktor request URL) — per-call attribution mirroring candor-rust's `str_arg`. Replaces
        // the old method-wide LDC sweep, which captured any host-shaped string in a host-bearing
        // method and so let a benign URL literal certify a runtime-computed host (AS-EFF-008
        // evasion) / a never-contacted host poison the allowlist. netHostLiteral rejects
        // non-hosts, so a benign non-URL arg adds nothing; the bare `Socket(host,port)` case is
        // handled above (netHostLiteral rejects a scheme-less bare host by design).
        if (isHostBearingOwner(min.owner) && min.desc.contains("Ljava/lang/String;")) {
            boolean hostCaptured = false;
            for (String lit : literalArgsInWindow(min, constLocals)) {
                String hl = netHostLiteral(lit);
                if (hl != null) {
                    ctx.hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(hl);
                    dir.addAll(EffectSet.ofNames(modelHostEffects(hl))); // §1 ⟨0.13⟩ Llm host-literal refinement
                    capturedHostHere = true;
                    hostCaptured = true;
                }
            }
            // LITERAL-HEAD of a runtime CONCAT arg (`getForObject("https://api.openai.com/v1/" + p, …)`):
            // the authority is fully present in the literal prefix → statically known (SPEC §1). Only when
            // no plain literal host was already captured, and only when the receiver-producing insn just
            // before this call is the concat (concatArgHost returns null otherwise — safe under-report).
            if (!hostCaptured) {
                String h = Literals.concatArgHost(min);
                if (h != null) {
                    ctx.hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(h);
                    dir.addAll(EffectSet.ofNames(modelHostEffects(h))); // §1 ⟨0.13⟩ Llm host-literal refinement
                    capturedHostHere = true;
                }
            }
        }
        // AS-EFF-008 surface COMPLETENESS (the masking fix): a Net reach whose host is structurally
        // invisible makes the method's host surface incomplete, so the gate must NOT certify it just
        // because OTHER (benign) hosts are visible. THREE structurally-invisible shapes:
        //  (1) a Net call on a host-LESS owner (gRPC ClientCalls, okhttp WebSocket, the reactive-HTTP
        //      terminals, a logging SocketAppender) — the host lives in a builder/config candor
        //      can't see;
        //  (2) a host-establishing Net call whose host is a RUNTIME string (a host-bearing owner,
        //      a leading `String` host arg, but no literal captured — `restTemplate.getForObject(
        //      runtimeUrl,…)`, `new Socket(runtimeHost,port)`, `InetAddress.getByName(runtimeHost)`).
        //  (3) a URL/URI Net TERMINAL (`openStream`/`openConnection`/`getContent`) whose host was
        //      fixed at a SEPARATE `new URL(String)` CONSTRUCTION (no Net effect, no String arg on
        //      the terminal). The split construct-then-use idiom: `new URL(getenv).openStream()`
        //      reaches a fully runtime-controlled host while a benign sibling `new URL("good").
        //      openStream()` populated hostsDirect and MASKED it (the AS-EFF-008 URL gate EVASION,
        //      formerly a value-flow backlog). FAIL-CLOSED unless the host is cheaply attributable
        //      to the terminal's receiver — inline `new URL("lit").openStream()` or a const-URL
        //      local — so the common inline-literal-URL case still certifies (urlTerminalHost).
        if (effect == Effect.NET) {
            boolean hostLessOwner = !isHostBearingOwner(min.owner);
            boolean runtimeStringHost = isHostBearingOwner(min.owner)
                    && min.desc.startsWith("(Ljava/lang/String;") && !capturedHostHere;
            boolean urlTerminal = isUrlValueOwner(min.owner) && !min.desc.startsWith("(Ljava/lang/String;")
                    && (min.name.equals("openStream") || min.name.equals("openConnection")
                            || min.name.equals("getContent"));
            if (urlTerminal) {
                String h = urlTerminalHost(min, urlLocals, constLocals);
                if (h != null) {
                    ctx.hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(h);
                    dir.addAll(EffectSet.ofNames(modelHostEffects(h))); // §1 ⟨0.13⟩ Llm host-literal refinement
                } else ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Net");
            }
            if (hostLessOwner || runtimeStringHost)
                ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Net");
        }
        // Table literals from THIS SQL-bearing call's OWN argument (the executed/prepared SQL) —
        // same per-call attribution. tablesInSql needs a leading SQL keyword so a non-SQL arg
        // yields nothing; a SQL-shaped log line in another statement is no longer mis-attributed.
        if (isSqlBearingOwner(min.owner) && min.desc.contains("Ljava/lang/String;")) {
            boolean anySqlLiteral = false;
            for (String lit : literalArgsInWindow(min, constLocals)) {
                anySqlLiteral = true;
                List<String> tl = tablesInSql(lit);
                if (!tl.isEmpty()) ctx.tablesDirect.computeIfAbsent(id, x -> new TreeSet<>()).addAll(tl);
            }
            // a SQL-establishing call with a RUNTIME query (String arg, no literal) — the table is
            // invisible to the gate (masking guard generalized to Db, sweep [0]). A literal SQL
            // with no table (`SELECT 1`) is visible-but-tableless, NOT incomplete.
            if (!anySqlLiteral)
                ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Db");
        }
    }

    /** Declarative-I/O call rules: Spring-Data/Jakarta repos (generated CRUD → Db), Feign +
     *  declarative HTTP clients (→ Net), Panache active-record and the AR/DAO base registries
     *  (inherited persistence verbs → Db). Returns whether the owner is one of those declarative
     *  types (`springTyped`), which the dispatch/cross-dep steps consult. */
    static boolean declarativeIoRules(AnalysisContext ctx, MethodScan s, MethodInsnNode min) {
        String id = s.id;
        EffectSet dir = s.dir;
        // Calls to a Spring Data repository / Feign client are I/O even though the
        // callee has no body candor can see (Spring synthesizes the impl at runtime).
        boolean springTyped = ctx.repoTypes.contains(min.owner) || ctx.feignTypes.contains(min.owner)
                || ctx.httpClientTypes.contains(min.owner);
        if (ctx.repoTypes.contains(min.owner)) {
            // The blanket Db is for the repository's GENERATED CRUD methods — abstract, no body
            // candor can see (Spring/Jakarta Data synthesize the impl at runtime). A `default`
            // method on the interface (or an inherited concrete one) DOES have a body whose
            // effects the CHA edge already attributes, so synthesizing Db there FABRICATES Db on
            // a pure default helper (a soundness sweep found `repo.greet()` → {Db} for a default
            // returning a constant). Only synthesize when the call resolves to NO visible body.
            ClassNode ro = ctx.byName.get(min.owner);
            boolean visibleBody = (ro != null && declaresConcrete(ro, min.name, min.desc))
                    || nearestConcreteSuper(min.owner, min.name, min.desc) != null;
            if (!visibleBody) {
                dir.add(Effect.DB);
                String tbl = ctx.repoTables.get(min.owner); // the declarative `tables` surface
                if (tbl != null) ctx.tablesDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(tbl);
            }
        }
        if (ctx.feignTypes.contains(min.owner)) dir.add(Effect.NET);
        // A declarative HTTP-client interface call is a wire call → Net (Object-protocol excluded so
        // a client's toString()/equals() doesn't fabricate Net).
        if (ctx.httpClientTypes.contains(min.owner) && !isConventionallyPure(min.name)) dir.add(Effect.NET);
        // Quarkus Panache ACTIVE-RECORD: a project class extends PanacheEntity[Base], so its
        // persist/delete/flush + inherited static finders (listAll/find/findById/count/…) are DB
        // ops — but the call-site owner is the PROJECT entity (`Fruit.listAll()`), not the external
        // base, so neither classify (keyed on the base) nor the repoTypes path fires; the inherited
        // body lives in Panache (unscanned) → silent-pure, a cardinal sin on the dominant Quarkus
        // persistence. Verb-gated AND hierarchy-gated (only fires when the owner extends a Panache
        // entity base), and skipped when the entity OVERRIDES the verb with its own body (that
        // body's effects are already attributed via the CHA edge — no fabrication, mirroring the
        // repoTypes default-method guard).
        if (PANACHE_ENTITY_VERBS.contains(min.name) && extendsPanacheEntity(min.owner)) {
            ClassNode eo = ctx.byName.get(min.owner);
            boolean ownBody = (eo != null && declaresConcrete(eo, min.name, min.desc))
                    || nearestConcreteSuper(min.owner, min.name, min.desc) != null;
            if (!ownBody) dir.add(Effect.DB);
        }
        // Active-record / DAO base classes (Ebean io.ebean.Model, ActiveJDBC Model, jOOQ DAOImpl) —
        // the SAME silent-pure shape as Panache: a persistence verb inherited into a project subtype,
        // called via the project owner. Verb+hierarchy-gated, skipped when the subtype overrides it
        // (that body's effects are attributed via the CHA edge — no fabrication).
        if (inheritsArDbVerb(min.owner, min.name)) {
            ClassNode ao = ctx.byName.get(min.owner);
            boolean ownBody = (ao != null && declaresConcrete(ao, min.name, min.desc))
                    || nearestConcreteSuper(min.owner, min.name, min.desc) != null;
            if (!ownBody) dir.add(Effect.DB);
        }
        return springTyped;
    }

    /** An INVOKEVIRTUAL/INVOKEINTERFACE dispatch: the CHA-exempt surface, monomorphic-receiver
     *  narrowing, bounded CHA with the closed-enum/sealed/closed-world refinements, and the honest
     *  Unknown branches (broad drop, missing project impl, unpinned JDK functional SAM). Returns true
     *  when the mono-receiver path resolved the call locally — the caller then skips the cross-dep
     *  join, exactly like the original `continue`. */
    static boolean virtualDispatch(AnalysisContext ctx, MethodScan s, MethodInsnNode min, String owner,
            Effect effect, boolean springTyped) {
        MethodNode mn = s.mn;
        String id = s.id;
        EffectSet dir = s.dir;
        Frame<ProvValue>[] provFrames = s.provFrames;
            // EXEMPT (SPEC §4): dispatch on the conventionally-pure java.lang.Object
            // surface — toString/hashCode/equals (+ erased Comparable.compareTo) — is NOT
            // CHA-fanned-out. Over `Object`, EVERY project class is a subtype, so one
            // `x.toString()` would edge every override in the jar; Kotlin emits exactly
            // that (`Any.toString` in string templates), which made kotlinx-coroutines
            // attribute one ServiceLoader-touching toString to 2160 methods (87% of the
            // jar). Same C2 trade as the Rust engine's dyn-Display/Error exemption — and
            // the documented caveat: an override of these that performs real I/O (that
            // kotlinx toString DOES reach a service load) is deliberately not attributed
            // at the dispatch site.
            // Class Hierarchy Analysis: dispatch reaches any project subtype's override.
            // BOUNDED for a CHA-EXEMPT method (the conventionally-pure Object protocol +
            // the function-interface / task-dispatch verbs every lambda/closure/Runnable
            // implements): attribute when the receiver resolves to FEW impls (a concrete
            // project type, an app's handful of Runnables — precise), but DROP the fan-out
            // when it's broad (a library's hundreds of FunctionN/Closure impls — the
            // kotlinx/scala/groovy smear that connected ~87% of a jar to one source). The
            // runtime-invoked verbs' bodies stay reachable via RUNTIME_OVERRIDES entry
            // points (incl. the function-interface rows) so a named implementor isn't
            // orphaned. (The smear, plus the four soundness holes an UNCONDITIONAL skip
            // opened — concrete-receiver toString, named-implementor orphaning, synchronous
            // Runnable.run, all caller-attribution — were found by /code-review max.)
            boolean dispatchExempt = isChaExemptMethod(min.owner, min.name, min.desc);
            // SOUNDNESS — monomorphic-receiver narrowing: if the receiver is PROVABLY a single
            // `new T` (the provenance pass above), this dispatch resolves to exactly the one
            // method T invokes — NOT its CHA siblings. `b = new Base(); b.compute()` must read
            // Base.compute alone, never the sibling Dirty.compute's Net. We narrow ONLY when the
            // receiver is provably a single new-type AND that type resolves a concrete impl in
            // its own chain; ANY other receiver (param/field/return/branch-merged → genuinely
            // polymorphic) falls through to the unchanged CHA over-approximation below, so a real
            // polymorphic effect is never lost. INVOKEINTERFACE is included: a provable `new T`
            // under an interface call still dispatches to T's concrete impl.
            String monoRecv = monomorphicReceiver(provFrames == null ? null
                    : provFrames[mn.instructions.indexOf(min)], min);
            if (monoRecv != null && ctx.byName.containsKey(monoRecv)) {
                // A provably-monomorphic PROJECT receiver (`new T`) has NO polymorphic siblings,
                // so this resolves to exactly T's method — never its CHA subtypes. `b = new
                // Base(); b.compute()` must read Base.compute alone, not the sibling Dirty's Net.
                // No concrete impl in T's own chain (impl in an unloaded super) → an ordinary
                // external call (no edge). Either way: resolved locally, so skip CHA, the Unknown
                // branches, AND cross-dep (a project call traces locally, never inherits a dep).
                String monoTarget = monomorphicTarget(monoRecv, min.name, min.desc);
                if (monoTarget != null) ctx.edges.get(id).add(monoTarget);
                return true;   // the original `continue`: resolved locally, skip the Unknown branches AND cross-dep
            }
            // CHA runs ONLY for a genuinely POLYMORPHIC receiver (monoRecv == null). An EXTERNAL
            // monoRecv (`new java.util.ArrayList<>()`) is PROVABLY that exact type, never a
            // project subtype, so CHA fan-out would FABRICATE: once transSupers files a `class
            // LoudList extends ArrayList { add(){…io…} }` under ArrayList, an unguarded fan-out
            // smears LoudList's effect onto every plain `new ArrayList().add()`. Skip CHA for it
            // — but DON'T `continue`: fall through to the cross-jar inheritance block below, since
            // the call is into an external/dependency method that may carry recorded effects.
            if (monoRecv == null) {
            List<String> cha = chaTargets(min.owner, min.name, min.desc);
            // BOUNDED CHA (SPEC §4): a dispatch over a local abstraction resolves to its
            // implementors only when the fan-out is NARROW (≤ CHA_FANOUT_LIMIT); a broad
            // fan-out is honest indeterminacy. Previously only EXEMPT methods (the pure
            // Object protocol) were bounded, so a non-exempt collection method (`isEmpty`/
            // `size`/`next`) over a deep hierarchy (scala-library: hundreds of impls) edged
            // to EVERY override and connected ~everything to a few effect sources — a
            // ThreadLocalRandom in one TrieMap.computeSize flooded 13k functions with Rand.
            // A CLOSED ENUM owner is exempt from the bound: its constant bodies are the WHOLE
            // visible+possible target set (no external subtype can exist), so resolving all of
            // them is exact, not the open-hierarchy over-approximation the limit guards against.
            // Without this, an enum state machine (process/read over 26/68 constants) drops past
            // the limit to a CIRCULAR Unknown (each state dispatches to the others) that smears
            // across its whole transitive caller set — the dominant Unknown driver on real OO.
            // CANDOR_CLOSED_WORLD: the user asserts the scanned classes are the complete world, so a
            // broad dispatch over a PROJECT-DEFINED type (in byName) is NOT indeterminate — its visible
            // impls ARE all the impls. Resolve it like a narrow dispatch (edge to every impl → the
            // fixpoint unions their effects, exact). Sound ONLY under the assertion + gated to project
            // types (an EXTERNAL interface — Comparator, a Kotlin FunctionN — keeps the bound: candor
            // can't enumerate its library impls even in a closed world, and those are the perf-
            // pathological hierarchies the limit exists for). Off by default → byte-identical.
            boolean closedWorldResolvable = ctx.closedWorld && ctx.byName.containsKey(min.owner);
            boolean broad = cha.size() > CHA_FANOUT_LIMIT && !isClosedHierarchy(min.owner)
                    && !closedWorldResolvable;
            // Record the owners where the FLAG changed the answer (would-be-broad, resolved anyway) —
            // the trigger for the closed-world hazard warning. Advisory bookkeeping only.
            if (closedWorldResolvable && cha.size() > CHA_FANOUT_LIMIT && !isClosedHierarchy(min.owner))
                ctx.closedWorldResolvedOwners.add(min.owner);
            // A NARROW java.util container-iteration dispatch (Iterator.next / Iterable etc.)
            // DOES fan out: skipping it under-reported a custom Iterable's effect at the loop
            // site (`for (x : customBag)` came back pure) — the §7.13 fuzzer's for-each form
            // catches it. The jts Rand "smear" the skip avoided is sound over-approximation, not
            // a reason to drop a real reachable effect; a broad fan-out still drops to Unknown.
            List<String> targets = broad ? List.of() : cha;
            ctx.edges.get(id).addAll(targets);
            // PROVABLE-INCOMPLETENESS: a sealed type whose permit-closure names an off-classpath
            // subtype is KNOWN-incomplete — the narrow path resolves only the visible permits and
            // would read silent-pure on the unseen one. Disclose Unknown (the visible impls' edges
            // above still carry their real effects; this adds the honest "+ an unseen permit").
            // Only matters on the narrow path; a broad sealed-unseen already drops to Unknown below.
            if (!broad && sealedHasUnseenPermit(min.owner)) {
                dir.add(Effect.UNKNOWN);
                ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>()).add(UnknownReason.of(UnknownReason.Kind.DISPATCH, owner + "." + min.name));
            }
            // A broad NON-exempt dispatch that DROPS project implementors → Unknown, not
            // silent-pure (an effectful body could be among the many we just dropped; exempt
            // methods are conventionally pure / runtime-entry, so they drop to nothing without
            // Unknown). The discriminator is "are we dropping PROJECT impls whose effects we'd
            // otherwise have propagated" — i.e. `cha` is non-empty — NOT "is the OWNER a project
            // type". `chaTargets` only ever returns project-defined CONCRETE bodies (it scans
            // byName, which holds project classes alone), so a non-empty `cha` IS that signal.
            // The owner can be an EXTERNAL interface (java.util.function.Supplier, Runnable,
            // Callable, java.util.List…) the project has ≥13 implementors of: bounded CHA drops
            // the whole fan-out, and the old `isProjectIfaceOrAbstract(min.owner)` gate was
            // FALSE for the external owner, so the caller went silently pure even though one of
            // the dropped project bodies wrote a file (the cardinal soundness sin). We preserve
            // the curated-κ posture for UBIQUITOUS stdlib dispatch (List.add / Iterator.next on
            // stdlib-only impls): there `cha` is EMPTY (no project class declares the body), so
            // no Unknown floods — they contribute nothing. (Found by /code-review max: 13+
            // project Suppliers, one effectful, over a single dispatch site.)
            // The exemption that suppresses this Unknown is ONLY the Object-protocol subset
            // (toString/hashCode/equals/compareTo — §4 pure even when overridden). The
            // function-object exemptions (Kotlin/Scala/Groovy invoke/apply/call) do NOT suppress
            // it: when the broad fan-out DROPS NAMED project impls (`!cha.isEmpty()`), one of
            // them can do real I/O, so honest Unknown — not silent-pure (the round-11 hole). This
            // INCLUDES a broad fan-out over synthetic Kotlin/Scala/Groovy LAMBDA classes: their
            // invoke()/apply() body is reachable ONLY through this dispatch edge (a `new Lam()`
            // edges <init>, NOT invoke — unlike a Java indy lambda whose body is edged at the indy
            // site), so suppressing the Unknown here AND dropping the edge made an effectful lambda
            // SILENT-PURE (a round-12 chaImplsAllSynthetic regression — reverted). A >12-lambda
            // higher-order site reporting Unknown is the SOUND over-approximation (the dispatcher
            // invokes an unresolvable function), not a bug; the precise effects are still captured
            // at each lambda's own rooted invoke() entry (the kotlin/Function RUNTIME_OVERRIDES row).
            if (broad && !isObjectProtocolExempt(min.name, min.desc) && effect == null && !springTyped
                    && (isProjectIfaceOrAbstract(min.owner) || !cha.isEmpty())) {
                dir.add(Effect.UNKNOWN);
                // Canonical `unknownWhy` vocabulary (SPEC §4, ⟨0.7⟩): a bounded-CHA broad
                // dispatch is an unresolved virtual dispatch → `dispatch:owner.member`. The
                // former `dispatch-broad:`/`dispatch-broad-ext:` (project vs external owner)
                // distinction is folded away — it is still an unresolved dispatch, resolved
                // identically by the frontier; the owner type carries the project/external info.
                ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>()).add(UnknownReason.of(UnknownReason.Kind.DISPATCH, owner + "." + min.name));
            }
            // Genuine unresolved dispatch: a PROJECT interface/abstract type that DECLARES
            // this method, with no visible concrete impl (DI-wired, external, or strategy)
            // → honest Unknown (SPEC §4). The `projectDeclaresMethod` gate is essential:
            // without it, a FRAMEWORK method merely INHERITED by a project abstract class
            // (Struts `Action.getServletContext`/`saveMessages`/`isTokenValid`, called on a
            // NEMsAction receiver) has no project override either, and would be mislabelled
            // Unknown — when it actually resolves to a superclass candor never loaded, i.e.
            // an ordinary external call (effect-free unless modelled, like every other lib
            // call). Only a method the project ITSELF declares is a real missing-impl. An
            // exempt method never raises Unknown (it's conventionally pure, or its body is a
            // runtime-invoked entry point).
            if (!broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                    && isProjectIfaceOrAbstract(min.owner)
                    && projectDeclaresMethod(min.owner, min.name, min.desc)) {
                dir.add(Effect.UNKNOWN);
                ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                        .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, owner + "." + min.name));
            }
            // A JDK FUNCTIONAL-INTERFACE SAM (`Runnable.run`, `Callable.call`,
            // `java.util.function.*`) invoked on an UNPINNED receiver with EMPTY CHA — the only
            // implementors are lambdas/method-refs whose bodies aren't reachable from THIS call
            // site (a field-stored handler `this.cb.run()`, a passed-in callback `h.run()`).
            // Both gates above miss it: empty CHA is never "broad" (so the broad-ext gate skips),
            // and the external functional-interface owner isn't a project iface (so the
            // missing-impl gate skips) — leaving the caller SILENTLY PURE though the lambda can
            // perform any effect (the 0.5.5 task_unpinned fuzzer used NAMED types, so it was
            // blind to the lambda-only case). Honest Unknown. Stdlib non-functional dispatch
            // (`list.size()`, `map.get()`) is unaffected — those owners aren't functional SAMs.
            if (!broad && targets.isEmpty() && !dispatchExempt && effect == null && !springTyped
                    && isJdkFunctionalSam(min.owner, min.name)) {
                // Canonical vocabulary (SPEC §4, ⟨0.7⟩): a JDK functional-SAM invoked on an
                // unpinned receiver (a field/param-stored handler `this.cb.run()`) is a
                // higher-order call on a function VALUE → `callback:`, not `dispatch:` (it does
                // not resolve to a class-hierarchy override, so it is correctly NOT a frontier source).
                String why = "callback:" + owner + "." + min.name;
                // PRIVATE FUNCTIONAL-PARAM FORWARDING: DEFER this Unknown only when (a) `mn` is
                // private (its call sites are nestmate-only → the values reaching the param are
                // fully enumerable) and (b) THIS SAM is provably invoked on that param itself
                // (samIsOnParam — receiver-identity, NOT a field/array-element/other F value).
                // runScan then resolves it to the lambdas the call sites pass, or restores this
                // Unknown if any was opaque. Otherwise emit the honest Unknown now.
                int pi = singleFunctionalParamIndex(mn);
                boolean forwardable = pi >= 0
                        && (mn.access & Opcodes.ACC_PRIVATE) != 0
                        && Type.getArgumentTypes(mn.desc)[pi].getInternalName().equals(min.owner)
                        && samIsOnParam(mn, min, provFrames, pi);
                if (forwardable) {
                    ctx.fwdSinkPending.add(id);
                    ctx.fwdSinkPendingWhy.put(id, new String[] { why });
                } else {
                    dir.add(Effect.UNKNOWN);
                    ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>()).add(UnknownReason.parse(why));
                }
            }
            } // end CHA block (monoRecv == null)
        return false;
    }

    /** Cross-jar inheritance (candor-spec §2): a call into a separately-analyzed dependency inherits
     *  its recorded effects (+ literal surfaces) via the stable method-ref hash, retrying on the
     *  provably-concrete receiver for supertype-typed calls. */
    static void crossDepJoin(AnalysisContext ctx, MethodScan s, MethodInsnNode min, Effect effect, boolean springTyped) {
        MethodNode mn = s.mn;
        String id = s.id;
        Frame<ProvValue>[] provFrames = s.provFrames;
        // Cross-jar inheritance (candor-spec §2): a call into a DEPENDENCY analyzed
        // separately — inherit its recorded effects via the stable method-ref hash. Only
        // for external, non-built-in, non-Spring calls (project calls trace locally;
        // reflection is already Unknown via classify).
        if (effect == null && !springTyped && !ctx.projectClasses.contains(min.owner)) {
            DepFn inh = ctx.crossDeps.get(min.owner + "." + min.name + min.desc);
            // INTERFACE/SUPERTYPE-typed dep call: `Store s = new FileStore(); s.save()`
            // compiles to INVOKEINTERFACE on `lib/Store`, but the dep report keys the body
            // by its CONCRETE owner (`lib/FileStore.save`). The static call-site owner misses
            // it, so the caller read SILENTLY PURE though the dep writes a file. When the
            // receiver is provably a single `new T` (the monomorphic receiver) and T is NOT a
            // project class (a dep type — a project T would have traced locally above), retry
            // the join on the concrete impl's hash. Sound: it is the EXACT runtime type, so
            // this is the one body the JVM dispatches to — never a CHA over-approximation.
            int xop = min.getOpcode();
            if (inh == null && (xop == Opcodes.INVOKEVIRTUAL || xop == Opcodes.INVOKEINTERFACE)) {
                String cRecv = monomorphicReceiver(provFrames == null ? null
                        : provFrames[mn.instructions.indexOf(min)], min);
                if (cRecv != null && !ctx.byName.containsKey(cRecv) && !cRecv.equals(min.owner))
                    inh = ctx.crossDeps.get(cRecv + "." + min.name + min.desc);
            }
            if (inh != null) {
                ctx.viaCross.computeIfAbsent(id, k -> EffectSet.empty()).addAll(inh.effects);
                if (!inh.hosts.isEmpty()) ctx.hostsDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.hosts);
                if (!inh.cmds.isEmpty()) ctx.cmdsDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.cmds);
                if (!inh.paths.isEmpty()) ctx.pathsDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.paths);
                if (!inh.tables.isEmpty()) ctx.tablesDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh.tables);
                // ⟨0.20⟩ a dep that itself reached an `unknown-host` (masked/runtime) taints the consumer
                // fail-closed: mark its Net surface incomplete so the consumer's netClass carries unknown-host
                // even though the dep's unresolved host never crossed into `hosts`. (Reuses the AS-EFF-008 marker.)
                if (inh.netClass.contains("unknown-host"))
                    ctx.surfaceIncomplete.computeIfAbsent(id, k -> new TreeSet<>()).add("Net");
            }
        }
    }

    /** A `NEW C` site: the class-load `<clinit>` edge, plus the anonymous/local-class and named
     *  task-type instantiation edges (the spawner inherits the body it hands to the runtime). */
    static void handleNewInsn(AnalysisContext ctx, MethodScan s, TypeInsnNode tin) {
        String id = s.id;
        // `new C` triggers C's class-load → its `<clinit>` runs (the `<init>` edge is added
        // separately by the INVOKESPECIAL above).
        clinitEdge(id, tin.desc);
        // ANONYMOUS/LOCAL class: it exists ONLY to be used via its supertype — typically
        // handed to a runtime executor (`new Thread(new Runnable(){…}).start()`) that
        // invokes run() OUTSIDE project code, so no in-project call site ever edges its
        // body. Edge the INSTANTIATION to its declared methods, mirroring how a lambda's
        // synthetic body is edged at its invokedynamic creation site (SEMANTICS §2's
        // closure-attribution rule — the Rust engines attribute thread::spawn closures to
        // the spawner; the scheduling method must inherit, not read pure). Gated on
        // outerMethod != null (set exactly for anonymous + local classes), so named
        // top-level/member classes are untouched. Found by the soundness fuzzer's
        // `thread_anon` form.
        ClassNode anonCn = ctx.byName.get(tin.desc);
        if (anonCn != null && anonCn.outerMethod != null) {
            for (MethodNode am : anonCn.methods)
                // Edge to the framework-INVOKABLE surface only: a PRIVATE method can't be an
                // override a runtime executor calls — it is reachable solely via an in-class
                // call from a live method (a normal edge), so a DEAD private helper must not
                // inherit at the instantiation site (it fabricated the helper's effect — e.g.
                // a never-called private `exec(..)` → a phantom Exec + command literal on the
                // spawner). A live private helper is still reached transitively via its caller.
                if (!am.name.startsWith("<") && (am.access & Opcodes.ACC_PRIVATE) == 0)
                    ctx.edges.get(id).add(methodId(tin.desc.replace('/', '.'), am.name, am.desc));
        } else if (anonCn != null && isTaskType(tin.desc)) {
            // A NAMED class that is a TASK TYPE (implements Runnable/Callable or extends Thread)
            // instantiated here is almost always handed to a runtime — `new Thread(new R()).start()`,
            // `es.submit(new R())`, `new MyThread().start()` — which invokes its run()/call()
            // OUTSIDE project code, so no in-project call site edges the body. Edge the
            // instantiation to the task SAM only (run/call — not every method; a named task can
            // have unrelated helpers), mirroring the anon case. The anon branch above is gated on
            // outerMethod, which is null for named top-level/member classes — this is the named
            // analog. RUNTIME_OVERRIDES also roots run/call; this attributes it to the spawner so
            // a blast-radius walk from the scheduler isn't pure. (Found by an async/threading sweep.)
            for (MethodNode am : anonCn.methods)
                if ((am.name.equals("run") || am.name.equals("call") || am.name.equals("compute"))
                        && (am.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) == 0)
                    ctx.edges.get(id).add(methodId(tin.desc.replace('/', '.'), am.name, am.desc));
        }
    }

    /** An invokedynamic site: string-concat toString reentry, lambda/method-ref creation edges
     *  (with the deferred/escape guards), external method-ref classification, and the
     *  dynamic-language bootstrap → Unknown. */
    static void handleInvokeDynamic(AnalysisContext ctx, MethodScan s, InvokeDynamicInsnNode idin) {
        MethodNode mn = s.mn;
        String id = s.id;
        EffectSet dir = s.dir;
        Frame<ProvValue>[] provFrames = s.provFrames;
        // STRING-CONCAT REENTRY (`"x" + obj`): javac compiles `+` over a non-String operand to a
        // makeConcatWithConstants/makeConcat invokedynamic whose StringConcatFactory bootstrap
        // calls each Object operand's toString. candor models the indy as pure, so an effectful
        // toString override read silent-pure. The operands are the indy's STACK args (their types
        // are idin.desc's parameter types); reenter toString on each whose declared type is a
        // LOCAL class with an effectful override (a String/Integer/external operand → no edge).
        if (provFrames != null && idin.bsm != null
                && idin.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
            Frame<ProvValue> cf = provFrames[mn.instructions.indexOf(idin)];
            for (ProvValue a : indyArgs(cf, idin)) reentryEdge(id, a, C_TOSTRING);
        }
        // Lambdas & method refs: the functional-interface factory's impl method (a project
        // `lambda$…` synthetic, or a referenced method) carries the body's effects. Edge to
        // it so they propagate here — else passing an effectful lambda looks pure.
        for (Object a : idin.bsmArgs) {
            // Only METHOD-kind handles (tags H_INVOKEVIRTUAL..H_INVOKEINTERFACE, i.e. >= 5)
            // are call targets carrying effects. FIELD-kind handles (H_GETFIELD..H_PUTSTATIC,
            // tags 1-4) also appear in bsmArgs — e.g. a `record`'s java.lang.runtime.ObjectMethods
            // bootstrap for equals/hashCode/toString passes an H_GETFIELD handle per component.
            // Their `desc` is a FIELD descriptor (no `()`), and a field read/write is pure, so
            // skip them: passing one to methodId would feed a field descriptor to
            // Type.getArgumentTypes and crash the whole scan.
            if (a instanceof Handle h && h.getTag() >= Opcodes.H_INVOKEVIRTUAL) {
                // A lambda that does NOT run at this creation site must not be edged here, else its
                // effect is misattributed to this method and (via the <clinit>/<init> + class-init
                // amplifier) SMEARED onto every method touching the class — a fabrication found by
                // the Kotlin/field sweep. Two shapes: (a) stowed into a deferred container
                // (`by lazy`, ThreadLocal.withInitial — attributed at the force site by
                // isDeferredForce); (b) escapes uninvoked — returned, or stored into a field/
                // collection, then run later via an unpinned SAM that discloses Unknown. A lambda
                // passed to a CALL that runs it (executor/stream/forEach/a forwarding sink) is NOT
                // matched, so its effect still propagates.
                boolean deferred = feedsDeferredFactory(idin) || lambdaEscapesUninvoked(idin);
                if (ctx.projectClasses.contains(h.getOwner())) {
                    if (!deferred) {
                        ctx.edges.get(id).add(methodId(h.getOwner().replace('/', '.'), h.getName(), h.getDesc()));
                        // An UNBOUND interface/abstract method-ref (`stream.forEach(Doer::go)`,
                        // `list.removeIf(Rule::stale)`) targets an ABSTRACT method with no body, so the edge
                        // above is silent-pure — the ubiquitous idiomatic-streams shape the LAMBDA form
                        // (`it -> it.go()`) already handled via its synthetic body's invokeinterface CHA.
                        // CHA the target over the owner's PROJECT impls exactly like a direct invokeinterface:
                        // a narrow fan-out edges every override; a broad (>limit, open-hierarchy) fan-out
                        // discloses Unknown, never silent-pure. A concrete method-ref / lambda synthetic
                        // target has no (further) project override → `cha` is self/empty → no change.
                        List<String> cha = chaTargets(h.getOwner(), h.getName(), h.getDesc());
                        boolean wouldBeBroad = cha.size() > CHA_FANOUT_LIMIT && !isClosedHierarchy(h.getOwner());
                        boolean broad = wouldBeBroad
                                && !(ctx.closedWorld && ctx.byName.containsKey(h.getOwner()));
                        // Same hazard bookkeeping as the direct-dispatch site: the flag changed the answer.
                        if (wouldBeBroad && !broad) ctx.closedWorldResolvedOwners.add(h.getOwner());
                        if (broad) {
                            dir.add(Effect.UNKNOWN);
                            ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                                    .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, h.getOwner() + "." + h.getName()));
                        } else {
                            ctx.edges.get(id).addAll(cha);
                        }
                    }
                    // A static method-ref / ctor-ref (`H::staticM`, `H::new`) TRIGGERS H's class
                    // load → its <clinit> runs (JVMS §5.5), exactly like a static call / NEW /
                    // static-field access. The other three triggers call clinitEdge; this one
                    // didn't, so a ref to a pure body on a class with an effectful <clinit> read
                    // silently pure (round-15 hole, the analog of the §5.5 superclass fix).
                    clinitEdge(id, h.getOwner());
                }
                else {
                    // A method REFERENCE to a NON-project method (`File::delete`,
                    // `System::getenv`) handed to a stream stage / functional API IS invoked by
                    // that stage — but it has no project node to edge to, so classify the target
                    // the same way the direct-call path does, else its effect is lost. The direct
                    // call (`f.delete()`) classifies; the ref (`removeIf(File::delete)`) did not —
                    // a silent-pure hole found by a streams/method-ref sweep. A pure target →
                    // null → nothing added (no fabrication).
                    Effect eff = Classifier.classify(h.getOwner().replace('/', '.'), h.getName(), h.getDesc());
                    if (eff != null) dir.add(eff);
                }
            }
        }
        // A bootstrap that is NOT one of the JVM's STRUCTURAL indy factories (lambda/method-ref
        // creation, string concat, record ObjectMethods, pattern-switch, constant-dynamic) is a
        // DYNAMIC-LANGUAGE dispatch bootstrap — Groovy's `IndyInterface.bootstrap`, JRuby, etc.
        // Its bsmArgs carry only a call-NAME string (no resolvable target handle), so the
        // dispatch is opaque exactly like reflection: it could reach any method and perform any
        // effect. Without this, compiled dynamic Groovy (the default, non-@CompileStatic mode)
        // dropped EVERY call — Fs/Exec/Net all silent-pure. Honest Unknown (SPEC §4), never
        // silent-pure. (Found by a JVM-dialect sweep on compiled Groovy.)
        if (idin.bsm != null && !STRUCTURAL_INDY_BSM.contains(idin.bsm.getOwner())) {
            dir.add(Effect.UNKNOWN);
            ctx.unknownWhy.computeIfAbsent(id, k -> new TreeSet<>())
                    .add(UnknownReason.of(UnknownReason.Kind.INDY, idin.bsm.getOwner().replace('/', '.')));
        }
    }

    /** A class's `<clinit>` runs once, at first class-load — triggered by a `new C`, a static method
     *  call on C, or a static field access on C. Edge to `C.<clinit>` from each such trigger so an
     *  effectful static initializer (`static { … }` / `static final X = readFile()`) propagates to the
     *  use site instead of looking pure. Over-approximates — the class may already be loaded by the
     *  time we reach this site — which is the SOUND direction (the I/O genuinely runs on first trigger).
     *  Only project classes that actually have a `<clinit>` (so the edge isn't dangling). */
    static void clinitEdge(String callerId, String internalOwner) {
        if (ctx().classesWithClinit.contains(internalOwner))
            ctx().edges.get(callerId).add(internalOwner.replace('/', '.') + ".<clinit>");
        // JVMS §5.5: initializing a class FIRST initializes its superclasses — so touching `Sub` runs
        // `Base.<clinit>` too. Edge to every project SUPERCLASS's <clinit> as well, else an effect in a base
        // class's static initializer is silently dropped when only the subclass is touched (round-13 hole;
        // the 0.5.2/0.5.3 clinit work fixed direct-class transitivity, not the superclass chain). Sound
        // over-approximation (a super-INTERFACE without a default method isn't initialized by a subclass load,
        // but edging its <clinit> at worst over-reports). transSupers is cached, so this is cheap.
        for (String sup : transSupers(internalOwner))
            if (!sup.equals(internalOwner) && ctx().classesWithClinit.contains(sup))
                ctx().edges.get(callerId).add(sup.replace('/', '.') + ".<clinit>");
    }


    /** CURATED deferred-execution containers: a CONSTRUCTION call that stows a lambda/Supplier/Function0
     *  into a field, paired with the FORCING method that later RUNS it. A construction is recognised by
     *  the static factory / constructor it uses; a forcing call by its `owner.name` on a GET* of a bound
     *  field. Kept SMALL and explicit — only containers whose getter provably runs the stored lambda — so
     *  forwarding is sound and field-scoped (an unrelated `.get()` on a non-tracked field binds nothing).
     *  Verified against real bytecode (javap) of the two repros. */
    // CONSTRUCTIONS — `owner.name(desc-prefix)` static factories that take the deferred lambda as an arg.
    // The kotlin `by lazy` compiler emits `kotlin/LazyKt.lazy(Function0)`; java emits
    // `java/lang/ThreadLocal.withInitial(Supplier)`. The lambda is the indy result pushed just before.
    static boolean isDeferredFactory(String owner, String name) {
        return (owner.equals("kotlin/LazyKt") && name.equals("lazy"))
                || (owner.equals("java/lang/ThreadLocal") && name.equals("withInitial"));
    }

    /** Whether the lambda an {@code idin} creates is IMMEDIATELY stowed into a curated deferred-execution
     *  container ({@code by lazy} → {@code LazyKt.lazy} / {@code new …LazyImpl}; {@code ThreadLocal.withInitial})
     *  rather than invoked at this site — found by scanning forward to the first consuming call. When it is,
     *  the lambda body must NOT be edged to this CREATION site: it does not run here (only at the force site,
     *  which {@link #isDeferredForce} attributes). Without this, a {@code val x by lazy { effect }} field
     *  attributes the effect to {@code <clinit>}, and since ANY static touch of the class triggers
     *  {@code <clinit>}, that effect smears onto every such method (a fabrication found by the Kotlin sweep). */
    static boolean feedsDeferredFactory(InvokeDynamicInsnNode idin) {
        int budget = 8;
        for (AbstractInsnNode n = idin.getNext(); n != null && budget-- > 0; n = n.getNext()) {
            if (n instanceof MethodInsnNode mi) {
                if (isDeferredFactory(mi.owner, mi.name)) return true;
                return mi.name.equals("<init>") && DEFERRED_LAZY_IMPLS.contains(mi.owner);
            }
            if (n instanceof InvokeDynamicInsnNode) return false; // another indy intervenes
        }
        return false;
    }

    /** A {@code java.util} collection/map method that STORES its argument for later (never invokes it):
     *  {@code put}/{@code add}/{@code set}/{@code push}/{@code offer}…. Deliberately EXCLUDES the invoking
     *  HOFs ({@code computeIfAbsent}/{@code merge}/{@code forEach}/{@code replaceAll}…), which DO run the
     *  lambda — those must keep the creation-site edge. */
    static boolean isStoringContainerCall(String owner, String name) {
        if (!owner.startsWith("java/util/")) return false;
        switch (name) {
            case "put": case "putIfAbsent": case "add": case "addFirst": case "addLast":
            case "set": case "push": case "offer": case "offerFirst": case "offerLast":
                return true;
            default: return false;
        }
    }

    /** Whether the lambda an {@code idin} creates ESCAPES THIS METHOD UNINVOKED — it is RETURNED
     *  (ARETURN), stored into a field (PUTFIELD/PUTSTATIC), or put into a collection/map (a storing
     *  container call) rather than passed to a call that runs it. Such a lambda does not RUN here; it runs
     *  at a later invocation on an unpinned receiver (a field-/collection-/return-value SAM), which
     *  discloses Unknown — so suppressing the creation-site edge here never silent-pures, it just stops the
     *  effect being misattributed to this method (and, via the <clinit>/<init> + class-init amplifier,
     *  SMEARED onto every method touching the class). The generic creation-edge is still added for a lambda
     *  passed to a CALL (executor/stream/forEach/a forwarding sink) — that path runs it. Conservative: the
     *  FIRST consuming op decides; an unrecognised call (which might invoke the lambda) keeps the edge. */
    static boolean lambdaEscapesUninvoked(InvokeDynamicInsnNode idin) {
        int budget = 6;
        for (AbstractInsnNode n = idin.getNext(); n != null && budget-- > 0; n = n.getNext()) {
            int op = n.getOpcode();
            if (op == Opcodes.ARETURN || op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC) return true;
            if (n instanceof MethodInsnNode mi) return isStoringContainerCall(mi.owner, mi.name);
            if (n instanceof InvokeDynamicInsnNode) return false;
        }
        return false;
    }
    // CONSTRUCTIONS via a direct constructor: `new kotlin/SynchronizedLazyImpl(Function0)` etc. (the
    // forms `LazyKt.lazy` delegates to; some kotlin versions / `lazy(mode){}` emit the impl ctor directly).
    static final Set<String> DEFERRED_LAZY_IMPLS = Set.of(
            "kotlin/SynchronizedLazyImpl", "kotlin/UnsafeLazyImpl", "kotlin/SafePublicationLazyImpl");
    // FORCING methods — `owner.name` (descriptor-insensitive: kotlin emits the parameterless
    // `Lazy.getValue()Ljava/lang/Object;` from the property getter; the 2-arg `getValue(thisRef,prop)`
    // KProperty form is the same forcing). A `ThreadLocal.get()` runs the withInitial Supplier on first
    // touch. `Lazy.getValue` / `Lazy.isInitialized` only the first reads value; getValue is THE force.
    static boolean isDeferredForce(String owner, String name) {
        return (owner.equals("kotlin/Lazy") && name.equals("getValue"))
                || (owner.equals("java/lang/ThreadLocal") && name.equals("get"));
    }
    // The container field types a forcing call must be reading, so an unrelated `.get()` (Optional, Map…)
    // on a same-named field never matches. Keyed by the field DESCRIPTOR at the GET* site.
    static final Set<String> DEFERRED_FIELD_DESCS =
            Set.of("Lkotlin/Lazy;", "Ljava/lang/ThreadLocal;");

    /** Bind each deferred field this `<init>`/`<clinit>` assigns to the lambda body it stores. Walk the
     *  body; at each PUTFIELD/PUTSTATIC of a container-typed field, scan BACK over the value-producing
     *  window for (a) a deferred FACTORY call (`LazyKt.lazy` / `ThreadLocal.withInitial`) or a `new
     *  …LazyImpl`, and (b) the INVOKEDYNAMIC (lambda/method-ref) feeding it. The indy's method handle is
     *  the body whose effect must forward. Bound under `owner/field:desc` (cross-class lookup at the force
     *  site). Conservative: if the construction or the lambda handle isn't found in the window, bind
     *  nothing (the §1 under-report direction — but then the constructor's own indy edge still charges
     *  <init>; only the forcing site stays unforwarded, never a fabrication). */
    static void bindDeferredFields(ClassNode cn, MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) {
            if (!(insn instanceof FieldInsnNode fi)) continue;
            if (fi.getOpcode() != Opcodes.PUTFIELD && fi.getOpcode() != Opcodes.PUTSTATIC) continue;
            if (!DEFERRED_FIELD_DESCS.contains(fi.desc)) continue;
            // Scan back: a deferred construction (factory call OR LazyImpl ctor) must appear before this
            // PUT, and an indy carrying a project method-ref handle must feed that construction's arg.
            boolean sawConstruction = false;
            Handle lambda = null;
            int depth = 0; // bound the scan to a few statements so we don't cross unrelated puts
            for (AbstractInsnNode n = fi.getPrevious(); n != null && depth < 64; n = n.getPrevious(), depth++) {
                if (n instanceof MethodInsnNode m) {
                    if (isDeferredFactory(m.owner, m.name)) sawConstruction = true;
                    else if (m.getOpcode() == Opcodes.INVOKESPECIAL && m.name.equals("<init>")
                            && DEFERRED_LAZY_IMPLS.contains(m.owner)) sawConstruction = true;
                } else if (n instanceof InvokeDynamicInsnNode idin && sawConstruction) {
                    for (Object a : idin.bsmArgs)
                        if (a instanceof Handle h && h.getTag() >= Opcodes.H_INVOKEVIRTUAL
                                && ctx().projectClasses.contains(h.getOwner())) {
                            lambda = h;
                            break;
                        }
                    if (lambda != null) break;
                } else if (n instanceof FieldInsnNode pf
                        && (pf.getOpcode() == Opcodes.PUTFIELD || pf.getOpcode() == Opcodes.PUTSTATIC)) {
                    break; // a prior store bounds this statement
                }
            }
            if (sawConstruction && lambda != null) {
                String key = fi.owner + "/" + fi.name + ":" + fi.desc;
                ctx().deferredFieldLambdas.computeIfAbsent(key, k -> new HashSet<>())
                        .add(methodId(lambda.getOwner().replace('/', '.'), lambda.getName(), lambda.getDesc()));
            }
        }
    }

    /** The field-key forced by a `Lazy.getValue` / `ThreadLocal.get` call, or null. The receiver is the
     *  container value produced by the nearest preceding GETFIELD/GETSTATIC of a container-typed field
     *  (bounded by a prior call/branch). `t.tl.get()` reads `Ti.tl` cross-class; `this.data$delegate
     *  .getValue()` reads the local field — both resolve to the GET* immediately before the call's args. */
    static String forcedFieldKey(MethodNode mn, MethodInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof FieldInsnNode fi
                    && (fi.getOpcode() == Opcodes.GETFIELD || fi.getOpcode() == Opcodes.GETSTATIC)
                    && DEFERRED_FIELD_DESCS.contains(fi.desc))
                return fi.owner + "/" + fi.name + ":" + fi.desc;
            // The receiver GET* sits in the call's own evaluation window; a prior call/branch/store bounds
            // it. (For the 2-arg KProperty `getValue(thisRef, prop)` the args are pushed AFTER the receiver,
            // so the receiver GET* is still the earliest field access reached scanning back — but a prior
            // MethodInsn for an arg would bound too early. We stop at the FIRST container GET* found, which
            // is correct for the parameterless getValue/get the kotlin/jdk compilers emit for property reads.)
            if (n instanceof JumpInsnNode) break;
        }
        return null;
    }


    /** The canonical Java serialization callback signatures (the Serializable/Externalizable contract).
     *  Their stream-typed descriptors are the giveaway; the runtime invokes them reflectively with no
     *  in-project call site, so without this their I/O is orphaned from every reachability root. */
    static boolean isSerializationCallback(String name, String desc) {
        switch (name) {
            case "readObject":       return desc.equals("(Ljava/io/ObjectInputStream;)V");
            case "writeObject":      return desc.equals("(Ljava/io/ObjectOutputStream;)V");
            case "readExternal":     return desc.equals("(Ljava/io/ObjectInput;)V");
            case "writeExternal":    return desc.equals("(Ljava/io/ObjectOutput;)V");
            case "readObjectNoData": return desc.equals("()V");
            case "readResolve":      return desc.equals("()Ljava/lang/Object;");
            case "writeReplace":     return desc.equals("()Ljava/lang/Object;");
            default:                 return false;
        }
    }


    /** A JDK FUNCTIONAL-INTERFACE single-abstract-method invocation — its only implementors are lambdas/
     *  method-refs whose bodies don't resolve from the call site, so an unpinned dispatch with no project
     *  impl is honest Unknown (never silent-pure). Restricted to the actual SAM names (not the package's
     *  concrete default methods); Runnable.run and Callable.call are the two outside the package. NOT the
     *  Kotlin/Scala/Groovy FunctionN (those stay isChaExemptMethod — their lambda effect is captured). */
    static boolean isJdkFunctionalSam(String owner, String name) {
        if (owner.startsWith("java/util/function/")) return FUNCTION_PKG_SAM.contains(name);
        if (owner.equals("java/lang/Runnable") && name.equals("run")) return true;
        if (owner.equals("java/util/concurrent/Callable") && name.equals("call")) return true;
        return false;
    }

    // ── Private functional-param forwarding (see fwdSink* fields) ──────────────────────────────────────

    /** A recognised JDK functional interface (the owners whose SAM raises a callback: Unknown). */
    static boolean isFunctionalIface(String internal) {
        return internal != null && (internal.startsWith("java/util/function/")
                || internal.equals("java/lang/Runnable") || internal.equals("java/util/concurrent/Callable"));
    }

    /** A JDK functional interface a LIBRARY HOF invokes on a passed instance — the java.util.function set
     *  plus the common library SAMs NOT in that package: `Comparator` (sort/sorted), `FileFilter`/
     *  `FilenameFilter` (File.listFiles). Broader than {@link #isFunctionalIface} on PURPOSE: kept separate
     *  so the private-forwarding param-count (which uses isFunctionalIface) is unaffected by this widening. */
    static boolean isHofFunctionalIface(String internal) {
        return isFunctionalIface(internal)
                || "java/util/Comparator".equals(internal)
                || "java/io/FileFilter".equals(internal)
                || "java/io/FilenameFilter".equals(internal)
                // AccessController.doPrivileged(action) SYNCHRONOUSLY runs action.run() (see isInvokingHof).
                // The action is a project class implementing one of these — its run() body performs the
                // real effect, so its SAM surface must propagate (found silent-pure on commons-vfs2's
                // PrivilegedFileReplicator.init/replicateFile → Net/Fs via a doPrivileged'd wrapped call).
                || "java/security/PrivilegedAction".equals(internal)
                || "java/security/PrivilegedExceptionAction".equals(internal);
    }

    /** Library method SIMPLE-NAMES that INVOKE a functional/Comparator/FileFilter argument's SAM (so a
     *  freshly-constructed project impl passed to one really runs and its effect must propagate). An
     *  ALLOWLIST — the safe direction: a name NOT here means no creation-site edge (a sound UNDER-report),
     *  whereas the old `!isStoringContainerCall` gate fired for ANY external non-store and FABRICATED on
     *  receive/store/compare sinks (requireNonNull / ofNullable / getOrDefault / Stream.of / indexOf /
     *  new TreeMap). Stream/Collection/Optional/Map higher-order verbs + the Comparator sorts + File
     *  listing. A STORE/box/null-check/compare/factory sink is deliberately ABSENT. */
    static boolean isInvokingHof(String name) {
        switch (name) {
            // Stream / Collection / Iterable element-consuming + transforming HOFs
            case "forEach": case "forEachOrdered": case "removeIf": case "replaceAll":
            case "map": case "mapToInt": case "mapToLong": case "mapToDouble": case "mapToObj":
            case "flatMap": case "filter": case "peek":
            case "anyMatch": case "allMatch": case "noneMatch": case "takeWhile": case "dropWhile":
            // Map HOFs
            case "computeIfAbsent": case "computeIfPresent": case "compute": case "merge":
            // Optional HOFs
            case "ifPresent": case "ifPresentOrElse":
            // Comparator-consuming sorts + selectors
            case "sort": case "sorted": case "min": case "max":
            // FileFilter / FilenameFilter
            case "listFiles": case "list":
            // AccessController.doPrivileged(PrivilegedAction|PrivilegedExceptionAction) runs action.run()
            // synchronously — a genuine invoking HOF (see isHofFunctionalIface).
            case "doPrivileged":
                return true;
            default:
                return false;
        }
    }

    /** The invokable SAM surface — non-private/static/abstract/`<init>` methods (the SAM override + any
     *  synthetic bridge) — of a PROJECT class that DIRECTLY implements a recognised functional interface;
     *  the bodies a library HOF invokes on it. Empty if the type is unknown, not a project class, or
     *  implements no such interface (a non-functional `new Foo()` edges nothing). */
    static Set<String> functionalSamSurface(String classInternal) {
        ClassNode cn = ctx().byName.get(classInternal);
        if (cn == null || cn.interfaces == null || cn.interfaces.stream().noneMatch(Candor::isHofFunctionalIface))
            return Set.of();
        Set<String> out = new HashSet<>();
        String dotted = classInternal.replace('/', '.');
        for (MethodNode m : cn.methods)
            if (!m.name.startsWith("<")
                    && (m.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT)) == 0)
                out.add(methodId(dotted, m.name, m.desc));
        return out;
    }

    /** The PROJECT method body a lambda/method-ref invokedynamic creates (its `lambda$…` synthetic or the
     *  referenced project method), or null — a non-lambda bootstrap, or a ref to an EXTERNAL method (no
     *  project node to resolve to → treated as opaque by the caller, keeping the sink's honest Unknown). */
    static String indyLambdaTarget(InvokeDynamicInsnNode idin) {
        if (idin.bsm == null || !idin.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")) return null;
        for (Object a : idin.bsmArgs)
            if (a instanceof Handle h && h.getTag() >= Opcodes.H_INVOKEVIRTUAL && ctx().projectClasses.contains(h.getOwner()))
                return methodId(h.getOwner().replace('/', '.'), h.getName(), h.getDesc());
        return null;
    }

    /** The descriptor-arg index (excluding `this`) of the SOLE functional-interface parameter of `mn`, or
     *  -1 if it has none or MORE than one (ambiguous → not eligible). */
    static int singleFunctionalParamIndex(MethodNode mn) {
        Type[] args = Type.getArgumentTypes(mn.desc);
        int found = -1;
        for (int i = 0; i < args.length; i++)
            if (args[i].getSort() == Type.OBJECT && isFunctionalIface(args[i].getInternalName())) {
                if (found >= 0) return -1;
                found = i;
            }
        return found;
    }

    /** The local-variable slot of declared argument {@code argIndex} (long/double occupy 2 slots; +1 for
     *  the {@code this} slot of an instance method). */
    static int paramLocalSlot(MethodNode mn, int argIndex) {
        int slot = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        Type[] args = Type.getArgumentTypes(mn.desc);
        for (int i = 0; i < argIndex; i++) slot += args[i].getSize();
        return slot;
    }

    /** The receiver ProvValue of instance call {@code min} in frame {@code f} — the stack slot just below
     *  the call's argument block; null if no frame or out of range. */
    static ProvValue receiverProv(Frame<ProvValue> f, MethodInsnNode min) {
        if (f == null) return null;
        int argSlots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) argSlots += a.getSize();
        int idx = f.getStackSize() - argSlots - 1;
        return idx >= 0 && idx < f.getStackSize() ? f.getStack(idx) : null;
    }

    /** Whether the SAM call {@code min} in {@code mn} is invoked on the UNMODIFIED parameter at descriptor
     *  index {@code argIndex} — the soundness anchor for deferring its callback Unknown. Proof by ProvValue
     *  reference identity: the entry frame holds the param's value in its local slot, and {@code
     *  copyOperation} preserves that instance through ALOAD and aliasing assignment; any transform that
     *  produces a DIFFERENT functional value (an AALOAD of an F[] element, a call/field result, a
     *  reassignment) yields a distinct instance, so the receiver is NOT {@code ==} the param and the SAM is
     *  correctly left as an honest Unknown. This is what stops a `more[0].accept()` / field-handler call in
     *  an otherwise-forwardable method from being silently suppressed. */
    static boolean samIsOnParam(MethodNode mn, MethodInsnNode min, Frame<ProvValue>[] provFrames, int argIndex) {
        if (provFrames == null || provFrames.length == 0) return false;
        ProvValue recv = receiverProv(provFrames[mn.instructions.indexOf(min)], min);
        return isParamValue(mn, recv, provFrames[0], argIndex);
    }

    /** True iff {@code v} is (by ProvValue reference identity) the value of declared parameter
     *  {@code argIndex} in the method's entry frame {@code f0}. The shared param-identity proof used by
     *  {@link #samIsOnParam} (single arg) and {@link #isOwnParam} (any arg). ReferenceEquality is
     *  INTENTIONAL: a ProvValue is a dataflow IDENTITY — the entry frame holds the param's instance and
     *  ALOAD/aliasing preserve it, while any transform (an array-element load, a call/field result, a
     *  reassignment) yields a DISTINCT instance — so {@code ==} answers "is this value the param itself";
     *  {@code .equals} would be wrong. */
    @SuppressWarnings("ReferenceEquality")
    static boolean isParamValue(MethodNode mn, ProvValue v, Frame<ProvValue> f0, int argIndex) {
        if (v == null || f0 == null) return false;
        int slot = paramLocalSlot(mn, argIndex);
        return slot < f0.getLocals() && f0.getLocal(slot) == v;
    }

    /** R17 — an I/O verb on an ABSTRACT {@code java.io} stream base (Reader/InputStream/Writer/OutputStream).
     *  A call on the abstract base means the concrete impl is unresolved; the verb decides it's genuine I/O
     *  (a read-, write-, or skip-prefixed method, or transferTo/append) rather than pure plumbing such as
     *  close/flush/mark/reset/ready — note {@code ready()} is read-PREFIXED but a non-blocking probe, not a
     *  read, so it is excluded explicitly. */
    static boolean isAbstractStreamIo(String internalOwner, String name) {
        boolean base = internalOwner.equals("java/io/Reader") || internalOwner.equals("java/io/InputStream")
                || internalOwner.equals("java/io/Writer") || internalOwner.equals("java/io/OutputStream");
        return base && !name.equals("ready") && (name.startsWith("read") || name.startsWith("write")
                || name.startsWith("skip") || name.equals("transferTo") || name.equals("append"));
    }

    /** R17 — true iff {@code v} is (by ProvValue identity) one of {@code mn}'s OWN declared parameters. An
     *  entry point's stream param is framework-injected, so reading it is I/O of unknown kind that must be
     *  DISCLOSED, not read silent-pure. {@code f0} is the method's entry frame ({@code provFrames[0]}). */
    static boolean isOwnParam(MethodNode mn, ProvValue v, Frame<ProvValue> f0) {
        int n = Type.getArgumentTypes(mn.desc).length;
        for (int i = 0; i < n; i++) if (isParamValue(mn, v, f0, i)) return true;
        return false;
    }

    /** The ProvValue of the {@code argIndex}-th declared argument (excluding the receiver) of call {@code min}
     *  in frame {@code f}, accounting for long/double double-slots; null if out of range or no frame. */
    static ProvValue argAt(Frame<ProvValue> f, MethodInsnNode min, int argIndex) {
        if (f == null) return null;
        Type[] args = Type.getArgumentTypes(min.desc);
        if (argIndex < 0 || argIndex >= args.length) return null;
        int total = 0, before = 0;
        for (int i = 0; i < args.length; i++) { if (i < argIndex) before += args[i].getSize(); total += args[i].getSize(); }
        int idx = f.getStackSize() - total + before;
        return idx >= 0 && idx < f.getStackSize() ? f.getStack(idx) : null;
    }

    /** The declared {@code (name,desc)} method of {@code cn}, or null. */
    static MethodNode findMethod(ClassNode cn, String name, String desc) {
        if (cn == null) return null;
        for (MethodNode m : cn.methods) if (m.name.equals(name) && m.desc.equals(desc)) return m;
        return null;
    }

    /** COLLECT (at a call site to a private functional-param sink): record the project lambda passed at the
     *  functional-param position, or mark the sink opaque if this site passes an unresolvable arg. */
    static void collectForwardingArg(String calleeDottedOwner, MethodInsnNode min, Frame<ProvValue> f) {
        MethodNode pm = findMethod(ctx().byName.get(min.owner), min.name, min.desc);
        if (pm == null || (pm.access & Opcodes.ACC_PRIVATE) == 0) return;
        int pi = singleFunctionalParamIndex(pm);
        if (pi < 0) return;
        String sinkId = methodId(calleeDottedOwner, min.name, min.desc);
        ProvValue arg = argAt(f, min, pi);
        if (arg != null && arg.fromIndy && arg.lambdaTarget != null)
            ctx().fwdSinkLambdas.computeIfAbsent(sinkId, k -> new HashSet<>()).add(arg.lambdaTarget);
        else
            ctx().fwdSinkOpaque.add(sinkId); // a field/param/external-ref/null arg → cannot prove the param's value
    }

    /** The §4 conventionally-pure Object protocol (formatting / equality / hashing / ordering) — a SUBSET
     *  of isChaExemptMethod. These stay pure even under a broad fan-out: an effectful override is spec-§4
     *  pure by convention, so dropping it raises NO Unknown. The OTHER exemptions (Kotlin/Scala/Groovy
     *  function-objects) are NOT here: a NAMED class implementing FunctionN can do real I/O, so a broad
     *  fan-out that DROPS such named impls must raise Unknown, not stay silent (the round-11 hole — a
     *  >12-impl unpinned `Function0.invoke` with one effectful NAMED impl read silently pure). */
    static boolean isObjectProtocolExempt(String name, String desc) {
        return (name.equals("toString") && desc.equals("()Ljava/lang/String;"))
                || (name.equals("hashCode") && desc.equals("()I"))
                || (name.equals("equals") && desc.equals("(Ljava/lang/Object;)Z"))
                || (name.equals("compareTo") && desc.equals("(Ljava/lang/Object;)I"));
    }


    /** Owners whose string ARG is genuinely a network HOST/endpoint (so a host-literal extraction is
     *  meaningful). Excludes KV/messaging clients (Jedis/Kafka/Rabbit/Mqtt/…) whose string args are
     *  keys/topics/routing-keys, not hosts — gating the literal sweep on this prevents fabricating a host
     *  from a Redis key that happens to look like host:port. */
    static boolean isHostBearingOwner(String internalOwner) {
        return internalOwner.equals("java/net/Socket") || internalOwner.equals("java/net/ServerSocket")
                || internalOwner.equals("java/net/InetSocketAddress") || internalOwner.equals("java/net/InetAddress")
                || internalOwner.equals("java/net/URL") || internalOwner.equals("java/net/URI")
                || internalOwner.equals("java/net/URLConnection") || internalOwner.equals("java/net/HttpURLConnection")
                || internalOwner.equals("javax/net/ssl/HttpsURLConnection")
                || internalOwner.equals("java/net/DatagramSocket") || internalOwner.equals("java/net/MulticastSocket")
                || internalOwner.equals("javax/net/ssl/SSLSocket")
                || internalOwner.startsWith("java/net/http/")
                || internalOwner.startsWith("org/springframework/web/")
                || internalOwner.startsWith("io/ktor/") || internalOwner.startsWith("javax/naming/");
    }

    /** Owners whose string arg is genuinely SQL (so a table extraction is meaningful) — JDBC + JPA + the
     *  SQL templates. Excludes Android SQLite execSQL/rawQuery? No — those ARE SQL; but a non-SQL Db client
     *  (a KV store classified Db) is excluded. */
    static boolean isSqlBearingOwner(String internalOwner) {
        return internalOwner.startsWith("java/sql/") || internalOwner.startsWith("javax/persistence/")
                || internalOwner.startsWith("jakarta/persistence/") || internalOwner.startsWith("org/hibernate/")
                || internalOwner.startsWith("org/springframework/jdbc/")
                || internalOwner.equals("android/database/sqlite/SQLiteDatabase")
                // The raw-SQL DRIVERS classified Db (0.5.24/0.5.25): their SQL string args carry tables too.
                // Without them, a method mixing an allowed JDBC table with a forbidden jOOQ/jdbi table reported
                // only the allowed one → AS-EFF-008 certified a method hitting the forbidden table (round-13
                // gate EVASION). NB: Mongo is deliberately ABSENT — a collection name is not SQL and tablesInSql
                // (needs a leading SQL keyword) extracts nothing from it anyway.
                || internalOwner.startsWith("org/jooq/") || internalOwner.startsWith("org/jdbi/")
                || internalOwner.startsWith("org/apache/ibatis/") || internalOwner.startsWith("org/neo4j/driver/")
                || internalOwner.startsWith("com/datastax/oss/") || internalOwner.startsWith("io/r2dbc/")
                || internalOwner.equals("org/springframework/data/jdbc/core/JdbcAggregateTemplate");
    }

    /** The §4 conventionally-pure object protocol — never an effect, even on an effect-bearing owner.
     *  Used to subtract fabrications from whole-owner classify rules. */
    static boolean isConventionallyPure(String method) {
        return method.equals("toString") || method.equals("hashCode") || method.equals("equals")
                || method.equals("getClass");
    }

    /** AWS v1/v2 client config getters that match the `get*` Net verb but make no request — pure local
     *  accessors of already-resolved config. Without this carve-out the `*Client` Net rule fabricates Net
     *  on a provably-pure getter (cardinal sin). NB: getBucketRegionViaHeadRequest is deliberately absent
     *  (it issues a HEAD → genuinely Net). */
    static boolean isAwsPureClientGetter(String method) {
        switch (method) {
            case "getRegion": case "getRegionName": case "getRegionNameFromAuthorityOrSigner":
            case "getSignerRegion": case "getSignerRegionOverride": case "getResourceUrl":
            case "getUrl": case "getCachedResponseMetadata": case "getServiceName":
            case "getEndpointPrefix": case "getClientConfiguration": case "getServiceNameIntern":
            // The pure config getters INHERITED from com.amazonaws.AmazonWebServiceClient (the base of
            // every v1 `Amazon*Client`): they match the `get*` verb but read cached local config / build a
            // signer object — no request. Without them the `*Client` Net rule still FABRICATED Net on a
            // provably-pure accessor (the round-11 finding — same class as getRegion, carve-out was
            // incomplete). getBucketRegionViaHeadRequest is deliberately absent (it issues a HEAD → Net).
            case "getTimeOffset": case "getSignerOverride": case "getRequestMetricsCollector":
            case "getMonitoringListeners": case "getSignerByURI": case "getEndpoint":
                return true;
            default: return false;
        }
    }

    static boolean supertypeMatches(String internalSuper, String row) {
        if (internalSuper.equals(row) || internalSuper.endsWith("/" + row)) return true;
        return row.endsWith("Function") && internalSuper.startsWith(row);
    }

    static boolean annoPresent(List<AnnotationNode> anns, String descSubstring) {
        if (anns == null) return false;
        for (AnnotationNode a : anns) if (a.desc != null && a.desc.contains(descSubstring)) return true;
        return false;
    }

    static boolean annoPresentAny(List<AnnotationNode> anns, List<String> subs) {
        for (String s : subs) if (annoPresent(anns, s)) return true;
        return false;
    }


    /** Whether any of the method's parameters carries one of the param-root markers (meta-annotation aware).
     *  ASM exposes per-parameter annotations as a {@code List<AnnotationNode>[]} (one slot per parameter). */
    static boolean anyParamAnnoMatches(MethodNode mn, List<String> markers) {
        return paramAnnoListHas(mn.visibleParameterAnnotations, markers)
                || paramAnnoListHas(mn.invisibleParameterAnnotations, markers);
    }

    static boolean paramAnnoListHas(List<AnnotationNode>[] params, List<String> markers) {
        if (params == null) return false;
        for (List<AnnotationNode> p : params)
            if (annoOrMetaMatches(p, markers)) return true;
        return false;
    }

    /** Whether any annotation in `anns` — DIRECTLY or via its META-annotation chain — matches a marker.
     *  Spring's stereotype model is composed annotations (`@GetMapping` is meta-annotated `@RequestMapping`;
     *  teams define `@ApiEndpoint = @GetMapping`), so a direct-only check orphans framework-invoked methods.
     *  Resolves each annotation TYPE's own annotations (project class via byName, else off candor's classpath
     *  via ASM), recursing with a visited-set + depth bound; JDK meta-annotations are skipped. The
     *  decoy-safe property holds: an UNRELATED `@com.myapp.GetMapping` whose meta-chain never reaches a real
     *  marker is not rooted (no fabrication). */
    static boolean annoOrMetaMatches(List<AnnotationNode> anns, List<String> markers) {
        if (anns == null) return false;
        Set<String> visited = new HashSet<>();
        for (AnnotationNode a : anns)
            if (a.desc != null && annoDescMatchesMeta(a.desc, markers, visited, 0)) return true;
        return false;
    }

    static boolean annoDescMatchesMeta(String desc, List<String> markers, Set<String> visited, int depth) {
        for (String m : markers) if (desc.contains(m)) return true;
        if (depth >= 5 || !desc.startsWith("L") || !desc.endsWith(";")) return false;
        String internal = desc.substring(1, desc.length() - 1);
        // a JDK meta-annotation (@Retention/@Target/@Documented/@Inherited) never reaches a framework marker
        if (internal.startsWith("java/") || !visited.add(internal)) return false;
        List<AnnotationNode> meta = annotationTypeAnnotations(internal);
        if (meta == null) return false;
        for (AnnotationNode a : meta)
            if (a.desc != null && annoDescMatchesMeta(a.desc, markers, visited, depth + 1)) return true;
        return false;
    }

    /** The visible annotations declared ON an annotation type (its meta-annotations), or null if
     *  unresolvable. A project annotation comes from byName; a framework one is read off candor's classpath
     *  via ASM (same posture as {@link #externalSupers}). Cached per type. */
    static List<AnnotationNode> annotationTypeAnnotations(String internal) {
        if (ctx().annoMetaCache.containsKey(internal)) return ctx().annoMetaCache.get(internal);
        List<AnnotationNode> out = null;
        ClassNode cn = ctx().byName.get(internal);
        if (cn != null) out = cn.visibleAnnotations;
        else {
            try {
                ClassNode an = new ClassNode();
                new ClassReader(internal).accept(an,
                        ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                out = an.visibleAnnotations;
            } catch (Throwable t) { /* not on candor's classpath → unresolvable, stays unrooted (sound) */ }
        }
        ctx().annoMetaCache.put(internal, out);
        return out;
    }

    static int firstLine(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) if (insn instanceof LineNumberNode ln) return ln.line;
        return 0;
    }

    /** Transitive supertypes (internal names) of a type. For a PROJECT class the supers come from its
     *  ClassNode; for an EXTERNAL ancestor they are read off candor's runtime classpath via ASM. The
     *  external walk matters because a project class can extend an external type (`class LoudList extends
     *  ArrayList`) and override a method DECLARED further up the EXTERNAL chain (`List.add`); without
     *  walking ArrayList's own supers, `LoudList` is never filed under `List`, so a base-typed dispatch on
     *  the grandparent interface (`l.add()` where `l: List`) finds no project subtype and goes silent-pure. */
    static Set<String> transSupers(String internal) {
        AnalysisContext c = ctx();   // hoist the ThreadLocal lookup — this is a hot, recursive, per-dispatch path
        Set<String> cached = c.transSupersCache.get(internal);
        if (cached != null) return cached;
        Set<String> r = new HashSet<>();
        c.transSupersCache.put(internal, r); // seed first to break cycles
        List<String> sup = new ArrayList<>();
        ClassNode cn = c.byName.get(internal);
        if (cn != null) {
            if (cn.superName != null) sup.add(cn.superName);
            if (cn.interfaces != null) sup.addAll(cn.interfaces);
        } else {
            sup.addAll(externalSupers(internal));  // a JDK/library ancestor — read its own supers off the classpath
        }
        for (String s : sup) { r.add(s); r.addAll(transSupers(s)); }
        return r;
    }

    /** Whether `internal` is a RUNTIME-INVOKED task type — implements Runnable/Callable or extends Thread
     *  (transitively, including through external supertypes via {@link #transSupers}). Such a class's
     *  run()/call() is invoked by an executor/scheduler with no in-project call site. */
    static boolean isTaskType(String internal) {
        Set<String> s = transSupers(internal);
        return s.contains("java/lang/Runnable") || s.contains("java/util/concurrent/Callable")
                || s.contains("java/lang/Thread") || s.contains("java/util/concurrent/ForkJoinTask");
    }


    // ===================================================================================================
    // IMPLICIT-CONTRACT-REENTRY (the same shape as the executor-handoff fix): a JDK sink candor models as
    // a pure leaf is in fact an OPAQUE call that re-enters user code through the JVM's implicit contract —
    // `String.valueOf(obj)` calls `obj.toString()`, `set.contains(key)` calls `key.equals/hashCode`,
    // `Collections.sort(list)` calls element.compareTo. candor never saw the callback, so an EFFECTFUL
    // override read silent-pure (the cardinal sin). We CHA the contract method over the ARGUMENT's declared
    // type and edge to its LOCAL override(s) — and ONLY those: chaTargets scans project classes alone, so a
    // String/Integer/external arg, or Object's default, yields NO local body and contributes nothing (no
    // flood, no fabrication). A PURE local override is edged too but propagates no effect. Reuses the exact
    // CHA the explicit `o.toString()` / `a.equals(b)` forms already use.
    // ===================================================================================================

    /** A reentry sink: which contract method(s) it triggers, and which argument position(s) carry the
     *  Object whose contract is re-entered. Resolution is by the sink's owner+name+desc. */
    static final String C_TOSTRING = "toString", C_EQUALS = "equals", C_HASHCODE = "hashCode", C_COMPARETO = "compareTo";
    static final String C_APPEND = "append", C_WRITE = "write";   // the WRITER side (R16): Appendable.append / Writer/OutputStream.write
    static final String C_READ = "read";   // the READER side (R32): Reader/InputStream.read driven by a concrete provided overload

    /** A DIRECT call to a concrete PROVIDED java.io method whose JDK body drives the abstract required
     *  method on the RECEIVER: `w.write(String)`/`w.append(..)`/`w.write(int)` → the abstract
     *  `Writer.write(char[],int,int)` override (C_WRITE); `r.read(char[])`/`r.skip(..)`/`in.transferTo(..)`
     *  → the abstract `Reader.read(char[],int,int)`/`InputStream.read()` override (C_READ). candor never
     *  descends into the JDK provided method, so a CUSTOM effectful subclass reached ONLY via a provided
     *  overload read silent-pure (R32 — the direct sibling of the R16 formatting-facade case; the facade
     *  drives the SINK ARG, this drives the RECEIVER). The driver contract for a name, or null. NOTE: keyed
     *  on the receiver's TYPE (a java.io stream base ancestor), NOT on `min.owner` — an `invokevirtual` owns
     *  the inherited overload at the receiver's STATIC type, which is usually the project subclass
     *  (`W$LoudWriter`), not the JDK base. Redundantly firing on the abstract override itself only adds the
     *  same edge normal CHA already resolves (a harmless dup). */
    static String ioDriverContract(String name) {
        if (name.startsWith("write") || name.equals("append")) return C_WRITE;
        if (name.startsWith("read") || name.startsWith("skip") || name.equals("transferTo")) return C_READ;
        return null;
    }

    /** Whether `internal` IS, or transitively EXTENDS, one of the four abstract java.io stream bases whose
     *  concrete provided methods drive an abstract required method (Writer/Reader/InputStream/OutputStream).
     *  Gates the R32 receiver reentry so only a genuine stream type resolves — a project class with a
     *  coincidental `write`/`read` method (no io ancestor) never triggers it. */
    static boolean isJavaIoStreamType(String internal) {
        if (internal == null) return false;
        if (IO_STREAM_BASES.contains(internal)) return true;
        for (String s : transSupers(internal)) if (IO_STREAM_BASES.contains(s)) return true;
        return false;
    }

    static final Set<String> IO_STREAM_BASES = Set.of(
            "java/io/Writer", "java/io/Reader", "java/io/InputStream", "java/io/OutputStream");

    /** If `min` constructs a JDK formatting facade WRAPPING a sink, the writer-side reentry contract for that
     *  sink (C_APPEND / C_WRITE); else null. `new Formatter(Appendable)` drives append; `new PrintWriter(
     *  Writer|OutputStream)` / `new PrintStream(OutputStream)` drive write. The File/String ctor overloads are
     *  file I/O (Fs, classified elsewhere), not a wrapped sink — excluded by the first-arg type. */
    static String formatterSinkCtor(String owner, String name, String desc) {
        if (!name.equals("<init>")) return null;
        if (owner.equals("java/util/Formatter") && desc.startsWith("(Ljava/lang/Appendable;")) return C_APPEND;
        if (owner.equals("java/io/PrintWriter")
                && (desc.startsWith("(Ljava/io/Writer;") || desc.startsWith("(Ljava/io/OutputStream;"))) return C_WRITE;
        if (owner.equals("java/io/PrintStream") && desc.startsWith("(Ljava/io/OutputStream;")) return C_WRITE;
        return null;
    }

    static boolean isToStringSink(String owner, String name, String desc) {
        if (desc == null) return false;
        // String.valueOf(Object) / String.format(...) / Objects.toString(Object[,String])
        if (owner.equals("java/lang/String"))
            return (name.equals("valueOf") && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;"))
                || name.equals("format");
        if (owner.equals("java/util/Objects") && name.equals("toString")) return true;
        // StringBuilder/StringBuffer.append(Object) (the (CharSequence)/(String)/(char[]) overloads do NOT
        // stringify via toString; only the (Object) one does).
        if ((owner.equals("java/lang/StringBuilder") || owner.equals("java/lang/StringBuffer"))
                && name.equals("append") && desc.equals("(Ljava/lang/Object;)L" + owner + ";")) return true;
        // PrintStream/PrintWriter print/println(Object)
        if ((owner.equals("java/io/PrintStream") || owner.equals("java/io/PrintWriter"))
                && (name.equals("print") || name.equals("println")) && desc.equals("(Ljava/lang/Object;)V")) return true;
        return false;
    }

    /** equals/hashCode-reentry sinks: a collection lookup/insert that hashes or compares the KEY/element by
     *  calling its equals + hashCode. */
    static boolean isEqualsHashSink(String owner, String name) {
        switch (owner) {
            case "java/util/Set": case "java/util/HashSet": case "java/util/LinkedHashSet":
            case "java/util/List": case "java/util/ArrayList": case "java/util/LinkedList":
            case "java/util/Collection":
                return name.equals("contains") || name.equals("add") || name.equals("remove")
                        || name.equals("indexOf") || name.equals("lastIndexOf");
            case "java/util/Map": case "java/util/HashMap": case "java/util/LinkedHashMap":
            case "java/util/concurrent/ConcurrentHashMap":
                return name.equals("get") || name.equals("containsKey") || name.equals("put")
                        || name.equals("remove") || name.equals("getOrDefault") || name.equals("putIfAbsent");
            default: return false;
        }
    }

    /** compareTo-reentry sinks: an ordering operation that sorts/orders elements by calling compareTo. */
    static boolean isCompareToSink(String owner, String name) {
        if (owner.equals("java/util/Collections") && name.equals("sort")) return true;
        if (owner.equals("java/util/Arrays") && name.equals("sort")) return true;
        if ((owner.equals("java/util/List") || owner.equals("java/util/ArrayList")
                || owner.equals("java/util/LinkedList")) && name.equals("sort")) return true;
        if (owner.equals("java/util/TreeSet") && (name.equals("add") || name.equals("contains"))) return true;
        if (owner.equals("java/util/TreeMap") && (name.equals("put") || name.equals("get")
                || name.equals("containsKey"))) return true;
        if (owner.equals("java/util/stream/Stream") && name.equals("sorted")) return true;
        return false;
    }

    /** CHA the contract method over the ARGUMENT's declared type, returning the LOCAL project override node
     *  id(s) to edge to. toString/equals/hashCode have fixed descriptors; compareTo is resolved by NAME
     *  (a `Comparable<T>` impl declares `compareTo(T)` plus a synthetic `compareTo(Object)` bridge — the
     *  bridge would CHA-resolve but matching the real typed override too is harmless and surer). EXTERNAL
     *  declType / Object's default / a non-overriding type → empty (chaTargets scans project classes only).
     *  This is the SAME chaTargets the explicit `o.toString()` form uses, so the implicit and explicit
     *  forms resolve identically. */
    static List<String> reentryTargets(String declType, String contract) {
        if (declType == null) return List.of();
        // By-NAME contracts (multiple overloads / erased descs): compareTo, and the WRITER side —
        // Appendable.append / Writer.write reached through a JDK formatting facade. Resolve to a project
        // subtype-or-self of declType declaring a concrete method of that name (any desc).
        if (contract.equals(C_COMPARETO) || contract.equals(C_APPEND) || contract.equals(C_WRITE)
                || contract.equals(C_READ)) {
            Set<String> out = new LinkedHashSet<>();
            for (String cName : ctx().subtypeIndex.getOrDefault(declType, List.of())) {
                ClassNode c = ctx().byName.get(cName);
                if (c == null) continue;
                for (MethodNode m : c.methods)
                    if (m.name.equals(contract) && (m.access & Opcodes.ACC_ABSTRACT) == 0
                            && (m.access & Opcodes.ACC_SYNTHETIC) == 0) // skip bridges; edge the real impl(s)
                        out.add(methodId(c.name.replace('/', '.'), m.name, m.desc));
            }
            return new ArrayList<>(out);
        }
        String desc = contract.equals(C_TOSTRING) ? "()Ljava/lang/String;"
                : contract.equals(C_HASHCODE) ? "()I"
                : "(Ljava/lang/Object;)Z"; // equals
        return chaTargets(declType, contract, desc);
    }

    /** Edge `callerId` to the LOCAL override(s) of `contract` on `argVal`'s declared type — the implicit
     *  reentry of a JDK sink. No-op when the arg type is external/Object-default/non-overriding (empty CHA),
     *  so a String/Integer/pure-override argument adds nothing. */
    static void reentryEdge(String callerId, ProvValue argVal, String contract) {
        if (argVal == null) return;
        for (String t : reentryTargets(argVal.declType, contract)) ctx().edges.get(callerId).add(t);
    }

    /** The ProvValue of argument `argPos` (0-based, in source order) of the call `min` in frame `f`, or null.
     *  Accounts for the receiver (present for non-static) and category-2 (long/double) arg slots. */
    static ProvValue callArg(Frame<ProvValue> f, MethodInsnNode min, int argPos) {
        if (f == null) return null;
        Type[] at = Type.getArgumentTypes(min.desc);
        if (argPos < 0 || argPos >= at.length) return null;
        int argSlots = 0;
        for (Type a : at) argSlots += a.getSize();
        int base = f.getStackSize() - argSlots; // first arg sits at the bottom of the call's arg block
        int idx = base;
        for (int i = 0; i < argPos; i++) idx += at[i].getSize();
        return idx >= 0 && idx < f.getStackSize() ? f.getStack(idx) : null;
    }

    /** ALL argument ProvValues of `min` in source order (skipping the category-2 second slots). Used by
     *  sinks whose Object operand could be any positional arg (e.g. a String.format-style varargs we resolve
     *  via the array-store scan instead — see reentryToStringForArrayStores). */
    static List<ProvValue> callArgs(Frame<ProvValue> f, MethodInsnNode min) {
        List<ProvValue> out = new ArrayList<>();
        if (f == null) return out;
        Type[] at = Type.getArgumentTypes(min.desc);
        int argSlots = 0;
        for (Type a : at) argSlots += a.getSize();
        int idx = f.getStackSize() - argSlots;
        for (Type a : at) {
            if (idx >= 0 && idx < f.getStackSize()) out.add(f.getStack(idx));
            idx += a.getSize();
        }
        return out;
    }

    /** ALL dynamic-argument ProvValues of an invokedynamic in source order (its desc's parameter types are
     *  the operand types on the stack). Used for string-concat operand reentry. */
    static List<ProvValue> indyArgs(Frame<ProvValue> f, InvokeDynamicInsnNode idin) {
        List<ProvValue> out = new ArrayList<>();
        if (f == null) return out;
        Type[] at = Type.getArgumentTypes(idin.desc);
        int argSlots = 0;
        for (Type a : at) argSlots += a.getSize();
        int idx = f.getStackSize() - argSlots;
        for (Type a : at) {
            if (idx >= 0 && idx < f.getStackSize()) out.add(f.getStack(idx));
            idx += a.getSize();
        }
        return out;
    }

    /** toString-reentry for the AASTORE operands feeding a varargs `Object[]` (String.format's `%s` args):
     *  the element values are packed into an array by `DUP; ICONST_i; <value>; AASTORE` BEFORE the call, so
     *  they are NOT on the stack at the call site. Walk backwards from `call` over the enclosing array-fill,
     *  reading the declared type of each AASTORE'd value from its frame, and edge toString on local effectful
     *  overrides. Bounded to the contiguous array-construction window (stops at a prior call/branch). */
    static void reentryFormatVarargs(String callerId, MethodNode mn, MethodInsnNode call, Frame<ProvValue>[] frames) {
        if (frames == null) return;
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            int op = n.getOpcode();
            // Stop at the array creation (ANEWARRAY Object) — the start of the varargs pack — or at any
            // other call / control-flow boundary, so we never read across into an unrelated computation.
            if (op == Opcodes.ANEWARRAY) break;
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode
                    || n instanceof LabelNode || n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode)
                break;
            if (op == Opcodes.AASTORE) {
                int fi = mn.instructions.indexOf(n);
                Frame<ProvValue> f = fi >= 0 && fi < frames.length ? frames[fi] : null;
                if (f != null && f.getStackSize() >= 1) {
                    ProvValue v = f.getStack(f.getStackSize() - 1); // the value being stored (top of stack)
                    reentryEdge(callerId, v, C_TOSTRING);
                }
            }
        }
    }


    /** A call that HANDS OFF a deferred task to a runtime that invokes it — an executor
     *  submit/execute/schedule verb, `new Thread(task)`, a CompletableFuture `*Async` stage, or a
     *  java.util.Timer schedule. Gated on the FIRST parameter being the task (always the deepest argument
     *  for these verbs), so the owner+verb set stays small and a project method that merely happens to be
     *  named `submit`/`schedule` is excluded by the owner gate. */
    static boolean isExecutorHandoff(String owner, String name, String desc) {
        if (desc == null) return false;
        boolean taskArg = false;
        for (String p : TASK_ARG_PREFIXES) { if (desc.startsWith(p)) { taskArg = true; break; } }
        if (!taskArg) return false;
        if (owner.equals("java/lang/Thread") && name.equals("<init>")) return true;
        if (EXECUTOR_OWNERS.contains(owner)
                && (name.equals("submit") || name.equals("execute") || name.equals("schedule")
                    || name.equals("scheduleAtFixedRate") || name.equals("scheduleWithFixedDelay"))) return true;
        if (owner.equals("java/util/concurrent/CompletableFuture") && COMPLETABLE_FUTURE_VERBS.contains(name))
            return true;
        return owner.equals("java/util/Timer") && TIMER_VERBS.contains(name);
    }

    static boolean isSyncCallbackInvoker(String owner, String name, String desc) {
        if (desc == null) return false;
        boolean taskArg = false;
        for (String p : TASK_ARG_PREFIXES) { if (desc.startsWith(p)) { taskArg = true; break; } }
        if (!taskArg) return false;
        // The `forEach`/`forEachOrdered`/`forEachRemaining` idiom invokes its functional argument
        // SYNCHRONOUSLY by contract across the ENTIRE JDK collection/stream/iterator hierarchy AND user
        // collections that mirror it — but the bytecode owner is the STATIC receiver type (`java/util/List`,
        // `java/util/ArrayList`, `java/util/HashSet`, a user `MyList`…), not the `java/lang/Iterable` where
        // the default method is declared, and candor-java has no JDK supertype index to normalize it. So an
        // owner-exact table silently misses the single most common form, `list.forEach(opaqueConsumer)`.
        // Match this family by NAME (owner-agnostic) — the sound + four-way-parity choice, since the Rust,
        // TS and Swift arms all key their sync-invoker check on the method name too. Over-disclosure stays
        // at the floor: only an OPAQUE functional arg reaches here (the caller gates on that); an inline
        // lambda keeps its edged effect. A user method merely NAMED forEach that stashes without calling is
        // vanishingly rare and disclosing Unknown there is the fail-safe direction anyway.
        if (FOR_EACH_FAMILY.contains(name)) return true;
        Set<String> names = SYNC_CALLBACK_INVOKERS.get(owner);
        return names != null && names.contains(name);
    }

    /** The synchronous for-each idiom, matched owner-agnostically (see {@link #isSyncCallbackInvoker}). */
    static final Set<String> FOR_EACH_FAMILY = Set.of("forEach", "forEachOrdered", "forEachRemaining");

    /** The TASK argument (arg0 — the deepest) of an executor hand-off call, from the provenance frame. */
    static ProvValue handoffTaskArg(Frame<ProvValue> f, MethodInsnNode min) {
        if (f == null) return null;
        int argSlots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) argSlots += a.getSize();
        int idx = f.getStackSize() - argSlots; // arg0 sits at the bottom of the call's argument block
        return idx >= 0 && idx < f.getStackSize() ? f.getStack(idx) : null;
    }


    /** Propagate the Fs read/write detail along the SAME call graph as effects, in a separate set. A
     *  function reaching the filesystem only across a jar boundary inherits `Fs` with NO recorded kind
     *  (FS_UNKNOWN), so the report presents an empty `fs` (no claim) rather than a misleading partial. */
    static Map<String, TreeSet<String>> fsFixpoint() {
        Map<String, TreeSet<String>> fs = new HashMap<>();
        for (var e : ctx().fsDirect.entrySet()) fs.put(e.getKey(), new TreeSet<>(e.getValue()));
        for (var e : ctx().viaCross.entrySet())
            if (e.getValue().contains(Effect.FS)) fs.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).add(FS_UNKNOWN);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : ctx().edges.keySet()) {
                TreeSet<String> add = new TreeSet<>();
                for (String c : ctx().edges.get(caller)) {
                    var ce = fs.get(c);
                    if (ce != null) add.addAll(ce);
                }
                if (add.isEmpty()) continue;
                var set = fs.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                set.addAll(add);
                if (set.size() != before) changed = true;
            }
        }
        return fs;
    }

    static Map<String, EffectSet> fixpoint() {
        return computeFixpoint(ctx().direct, ctx().edges, ctx().viaCross);
    }

    /** The PURE least-fixpoint of effect propagation over the call graph — factored out of
     *  {@link #fixpoint()} with its three inputs passed explicitly (no static reads) so it is
     *  unit-testable with synthetic graphs. {@code direct} = each fn's own-body effects;
     *  {@code edges} = caller → callees; {@code viaCross} = effects inherited from a CANDOR_DEPS
     *  sibling report. Result: each fn's transitive (inferred) effect set. */
    static Map<String, EffectSet> computeFixpoint(
            Map<String, EffectSet> direct,
            Map<String, Set<String>> edges,
            Map<String, EffectSet> viaCross) {
        Map<String, EffectSet> eff = new HashMap<>();
        for (var k : direct.keySet()) eff.put(k, direct.get(k).copy());
        // Seed in effects inherited via cross-jar calls (kept out of `direct` — they're not in this
        // method's own body; they appear in `inferred` and propagate transitively, like the Rust impl).
        for (var e : viaCross.entrySet()) eff.computeIfAbsent(e.getKey(), k -> EffectSet.empty()).addAll(e.getValue());
        // WORKLIST least-fixpoint. The old `while (changed) { for caller in edges.keySet() }` re-swept EVERY
        // caller on every pass, and the pass count equals the longest back-to-front call chain — up to V, so
        // O(V²) on deep whole-program graphs. Instead, when eff[f] grows, re-enqueue only the callers whose
        // union reads eff[f] (a callee→callers reverse index). Same monotone set-union (confluent) least
        // fixpoint → order-independent → the RESULT is identical, in amortized O(V + E·effects).
        Map<String, List<String>> callersOf = new HashMap<>();
        for (var caller : edges.keySet())
            for (String callee : edges.get(caller))
                callersOf.computeIfAbsent(callee, k -> new ArrayList<>()).add(caller);
        Deque<String> queue = new ArrayDeque<>(edges.keySet());
        Set<String> queued = new HashSet<>(edges.keySet());
        while (!queue.isEmpty()) {
            String caller = queue.pollFirst();
            queued.remove(caller);
            var set = eff.computeIfAbsent(caller, k -> EffectSet.empty());
            int before = set.size();
            for (String callee : edges.get(caller)) {
                // A class-load TRIGGER edge propagates the `<clinit>`'s FULL transitive effects (spec §5:
                // `inferred` is the transitive fixpoint over edges). Touching the class runs its static
                // initializer, which can transitively reach whatever the static block calls or constructs,
                // so the trigger site CAN reach those effects — sound over-approximation ("can reach"). A
                // prior direct-only narrowing here under-reported (the §7.13 soundness fuzzer caught it on
                // every clinit form: a real effect threaded through a static block came back pure). The
                // guava-construction `Log` smear that narrowing avoided is sound-but-imprecise — the target
                // of a separate precision effort, never a reason to drop a real reachable effect.
                var ce = eff.get(callee);
                if (ce != null) set.addAll(ce);
            }
            if (set.size() != before) {   // caller grew → its own callers must re-absorb from it
                List<String> cs = callersOf.get(caller);
                if (cs != null) for (String c : cs) if (queued.add(c)) queue.addLast(c);
            }
        }
        return eff;
    }

    /** For a call ALREADY classified `Fs`, the read/write direction its verb implies: ["read"],
     *  ["write"], ["read","write"] (e.g. Files.copy), or [] when the verb doesn't say (so we make no
     *  claim). Keyed off the java.io / java.nio.file vocabulary — a syntactic refinement of an effect
     *  candor already proved, NOT a soundness claim. */
    static List<String> fsKind(String owner, String method) {
        if (method.equals("<init>")) { // a stream constructor reveals direction by its type
            if (owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileReader")) return List.of("read");
            if (owner.equals("java.io.FileOutputStream") || owner.equals("java.io.FileWriter")) return List.of("write");
            return List.of(); // RandomAccessFile (mode-dependent), File (no I/O) — no claim
        }
        if (method.equals("copy")) return List.of("read", "write");
        switch (method) {
            case "write": case "writeString": case "newOutputStream": case "newBufferedWriter":
            case "createFile": case "createDirectory": case "createDirectories": case "createTempFile":
            case "createTempDirectory": case "delete": case "deleteIfExists": case "move":
            case "setAttribute": case "setLastModifiedTime": case "setPosixFilePermissions":
            case "setOwner": case "createLink": case "createSymbolicLink": case "mkdir": case "mkdirs":
            case "renameTo": case "createNewFile": case "setReadable": case "setWritable":
            case "setExecutable": case "setLastModified": case "deleteOnExit": case "truncate":
                return List.of("write");
            case "readAllBytes": case "readString": case "readAllLines": case "lines":
            case "newInputStream": case "newBufferedReader": case "exists": case "notExists":
            case "isDirectory": case "isRegularFile": case "isReadable": case "isWritable":
            case "isExecutable": case "size": case "length": case "getLastModifiedTime":
            case "readAttributes": case "getAttribute": case "list": case "listFiles": case "walk":
            case "find": case "newDirectoryStream": case "isSameFile": case "mismatch":
            case "probeContentType": case "canRead": case "canWrite": case "canExecute":
            case "lastModified": case "toRealPath": case "readSymbolicLink": case "isHidden":
            case "getFreeSpace": case "getTotalSpace": case "getUsableSpace":
                return List.of("read");
            default: break;
        }
        if (method.startsWith("write") || method.equals("append")) return List.of("write");
        if (method.startsWith("read")) return List.of("read");
        return List.of();
    }


    static boolean kappaCovers(String pkg) {
        for (String p : KAPPA_COVERED_PREFIXES) {
            if (pkg.equals(p) || (pkg.length() > p.length() && pkg.charAt(p.length()) == '.' && pkg.startsWith(p))) return true;
        }
        return false;
    }

    /** A Spring type whose NAME follows the framework's "this class performs I/O" convention — the *Template
     *  (JdbcTemplate/RestTemplate/RedisTemplate/MessagingTemplate/…), *Operations (ValueOperations/
     *  ElasticsearchOperations/…), *Repository (Spring Data), *Gateway (integration) families. Used by the
     *  structural Spring-floor fix to DISCLOSE Unknown on an unmodeled member of such a type instead of
     *  silently dropping it. Pure Spring utility classes (StringUtils/ObjectUtils/Assert/ClassUtils/…) do NOT
     *  match these suffixes, so they stay floored (no disclosure flood). `internalOwner` is the slash-form. */
    static boolean isSpringIoOwner(String internalOwner) {
        int slash = internalOwner.lastIndexOf('/');
        String simple = slash >= 0 ? internalOwner.substring(slash + 1) : internalOwner;
        int dollar = simple.lastIndexOf('$');           // a nested type — use its own simple name
        if (dollar >= 0) simple = simple.substring(dollar + 1);
        return simple.endsWith("Template") || simple.endsWith("Operations")
                || simple.endsWith("Repository") || simple.endsWith("Gateway");
    }

    /** Proven-PURE accessors/factories/inert ctors on owners whose effect is otherwise whole-owner
     *  (File→Fs, Socket→Net, Clock, Random→Rand, ZipFile/JarFile→Fs, Clipboard). The cardinal sin of
     *  an effect-checker is fabricating an effect on a PURE method, so we SUBTRACT only the methods we
     *  can prove do NO I/O / read NO entropy / read NO clock — and KEEP the whole-owner effect for
     *  everything else (the safe direction: when in doubt, KEEP it effectful). Mirrors the verb-gating
     *  already done for java.nio.file.Files, java.sql.Statement, kotlin.io.FilesKt, ktor, InetAddress,
     *  JNDI. Consulted by `classify` BEFORE the owner-match fires; returns true ⇒ classify returns null.
     *  CRITICAL: this may only ever REMOVE a fabrication, never introduce an under-report, so the
     *  effectful members of each type (delete/exists/getCanonicalPath; getInput/OutputStream; instant;
     *  nextInt/getSeed; entries; getContents) are deliberately ABSENT here and keep firing. */
    static boolean isPureHandleAccessor(String owner, String method) {
        switch (owner) {
            // java.io.File — a File is just an immutable PATHNAME object; these touch NO filesystem.
            // The inert ctor (`new File(...)`) does ZERO I/O (it stores the path string). The effectful
            // members — delete/exists/isDirectory/mkdir/listFiles/getCanonicalPath/getCanonicalFile
            // (resolve symlinks → touch the FS) — are NOT listed, so they keep returning Fs.
            case "java.io.File":
                return method.equals("<init>") || method.equals("getName") || method.equals("getParent")
                        || method.equals("getParentFile") || method.equals("getPath")
                        || method.equals("getAbsolutePath") || method.equals("getAbsoluteFile")
                        || method.equals("isAbsolute") || method.equals("toURI") || method.equals("toPath")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals")
                        || method.equals("compareTo");
            // java.net.Socket family — these read fields cached on the handle (the port/address bound at
            // construct/connect time, the closed/bound/connected flags); they do NO wire I/O. The I/O
            // boundary (getInputStream/getOutputStream/connect/bind/send/receive/close) is NOT listed.
            case "java.net.Socket":
            case "java.net.ServerSocket":
            case "java.net.DatagramSocket":
            // MulticastSocket extends DatagramSocket and javax.net.ssl.SSLSocket extends Socket — a receiver
            // TYPED as the subclass emits owner=subclass for the INHERITED pure accessors, which sailed past
            // the Socket carve-out and got fabricated Net by the subclass's whole-owner Net rule (the cardinal
            // sin; found by a fabrication sweep — these survived 14 rounds). They inherit exactly this
            // accessor set. (SSLSocket's OWN pure config surface is handled in its case below.)
            case "java.net.MulticastSocket":
                return method.equals("getPort") || method.equals("getLocalPort")
                        || method.equals("getInetAddress") || method.equals("getLocalAddress")
                        || method.equals("getLocalSocketAddress") || method.equals("getRemoteSocketAddress")
                        || method.equals("isClosed") || method.equals("isBound") || method.equals("isConnected")
                        || method.equals("isInputShutdown") || method.equals("isOutputShutdown")
                        || method.equals("getReuseAddress") || method.equals("getSoTimeout")
                        || method.equals("getTimeToLive") || method.equals("getInterface")
                        || method.equals("getNetworkInterface") || method.equals("getLoopbackMode")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // javax.net.ssl.SSLSocket — the inherited Socket accessors PLUS its own pure HANDSHAKE-CONFIG
            // surface (cipher-suite/protocol/parameter get+set touch NO wire). Only startHandshake /
            // getInputStream / getOutputStream / getSession (forces a handshake) do I/O — NOT listed → Net.
            case "javax.net.ssl.SSLSocket":
                return method.equals("getPort") || method.equals("getLocalPort")
                        || method.equals("getInetAddress") || method.equals("getLocalAddress")
                        || method.equals("getLocalSocketAddress") || method.equals("getRemoteSocketAddress")
                        || method.equals("isClosed") || method.equals("isBound") || method.equals("isConnected")
                        || method.equals("isInputShutdown") || method.equals("isOutputShutdown")
                        || method.equals("getReuseAddress") || method.equals("getSoTimeout")
                        || method.equals("getEnabledCipherSuites") || method.equals("getSupportedCipherSuites")
                        || method.equals("setEnabledCipherSuites") || method.equals("getEnabledProtocols")
                        || method.equals("getSupportedProtocols") || method.equals("setEnabledProtocols")
                        || method.equals("getSSLParameters") || method.equals("setSSLParameters")
                        || method.equals("getUseClientMode") || method.equals("setUseClientMode")
                        || method.equals("getNeedClientAuth") || method.equals("setNeedClientAuth")
                        || method.equals("getWantClientAuth") || method.equals("setWantClientAuth")
                        || method.equals("getEnableSessionCreation") || method.equals("setEnableSessionCreation")
                        || method.equals("addHandshakeCompletedListener")
                        || method.equals("removeHandshakeCompletedListener")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // java.time.Clock — the factories (systemUTC/system/fixed/offset/tick*) build a Clock object
            // and the accessors (getZone/withZone) read its zone; NONE read the wall clock. The actual
            // clock reads — instant()/millis() — are NOT listed, so they keep returning Clock.
            case "java.time.Clock":
                return method.equals("systemUTC") || method.equals("systemDefaultZone")
                        || method.equals("system") || method.equals("fixed") || method.equals("offset")
                        || method.equals("tick") || method.equals("tickMillis") || method.equals("tickSeconds")
                        || method.equals("tickMinutes") || method.equals("getZone") || method.equals("withZone")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // java.util.Random / SecureRandom / ThreadLocalRandom / SplittableRandom — these read NO
            // entropy: getInstance/getInstanceStrong build a generator, getAlgorithm/getProvider read
            // its metadata. ThreadLocalRandom.current() is a pure thread-local FACTORY: it returns the
            // singleton `instance` and, on first call, seeds the thread's state from an atomic counter
            // (mixMurmur64 of a counter) — NOT from OS entropy/a CSPRNG (verified in the JDK source);
            // the actual draws come later. The draws (next*/ints/longs/doubles/getSeed/generateSeed/
            // setSeed) are NOT listed, so they keep returning Rand.
            case "java.util.Random":
            case "java.security.SecureRandom":
            case "java.util.concurrent.ThreadLocalRandom":
            case "java.util.SplittableRandom":
                return method.equals("getInstance") || method.equals("getInstanceStrong")
                        || method.equals("getAlgorithm") || method.equals("getProvider")
                        || method.equals("getParameters") || method.equals("current")
                        || method.equals("toString");
            // java.util.zip.ZipFile / java.util.jar.JarFile — getName returns the cached path, size()
            // returns the cached entry count (no re-read of the archive). The ctor (OPENS the archive),
            // entries()/getInputStream()/getEntry()/stream() (READ it) are NOT listed → keep Fs.
            case "java.util.zip.ZipFile":
            case "java.util.jar.JarFile":
                return method.equals("getName") || method.equals("size") || method.equals("toString");
            // java.awt.datatransfer.Clipboard — getName returns the clipboard's label; the actual
            // get/setContents (read/write the system clipboard) are NOT listed → keep Clipboard.
            case "java.awt.datatransfer.Clipboard":
                return method.equals("getName") || method.equals("toString");
            // java.nio.channels.FileChannel / AsynchronousFileChannel — isOpen() is `!closed`, a pure
            // field read inherited from AbstractInterruptibleChannel (verified in the JDK source). The
            // real file I/O — read/write/map/force/truncate/transferTo/transferFrom/lock/size — is NOT
            // listed → keeps Fs. DELIBERATELY ABSENT: position() (the no-arg getter). Despite looking
            // like a cached accessor, FileChannelImpl.position() issues an lseek syscall (nd.seek(fd,-1))
            // to read the current OS file-pointer, so it is genuine Fs I/O — the SAFETY RULE (keep the
            // effect when not PROVABLY pure) forbids subtracting it.
            case "java.nio.channels.FileChannel":
            case "java.nio.channels.AsynchronousFileChannel":
                return method.equals("isOpen")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            // java.nio.channels socket channels — the accessors read fields cached on the handle (open
            // flag, connect state, blocking mode, the addresses bound/connected at setup time) and
            // socket() lazily wraps the channel in an adaptor object; NONE touch the wire (verified in
            // SocketChannelImpl/ServerSocketChannelImpl/DatagramChannelImpl). The network boundary —
            // connect/finishConnect/read/write/send/receive/bind/accept — is NOT listed → keeps Net.
            case "java.nio.channels.SocketChannel":
            case "java.nio.channels.ServerSocketChannel":
            case "java.nio.channels.DatagramChannel":
                return method.equals("isOpen") || method.equals("isConnected")
                        || method.equals("isConnectionPending") || method.equals("isBlocking")
                        || method.equals("getLocalAddress") || method.equals("getRemoteAddress")
                        || method.equals("socket")
                        // config/registration verbs touch NO wire — a whole-owner Net rule fabricated Net on
                        // them (cardinal sin, found by a NIO sweep). setOption sets a socket option,
                        // configureBlocking sets a flag, register registers interest with a selector,
                        // supportedOptions returns a static Set, bind selects a local endpoint.
                        || method.equals("setOption") || method.equals("getOption")
                        || method.equals("supportedOptions") || method.equals("configureBlocking")
                        || method.equals("register") || method.equals("validOps")
                        || method.equals("toString") || method.equals("hashCode") || method.equals("equals");
            default:
                return false;
        }
    }

    // The `Log` effect means PRODUCING a log record. The genuine emit surface across slf4j / jul /
    // log4j2 / logback is a NARROW, NAMED set of verbs on the Logger (and the fluent builder's terminal
    // `log()`, the backend Appender/Handler append). Everything else in those packages — Markers, Levels,
    // ThreadContext maps, Message data types, formatters, config/registry lookups, util helpers — emits
    // NOTHING. The classify() gate therefore fires Log ONLY on these verbs (VERB-PRECISE), letting every
    // other logging-package method fall through to its real, transitively-analysed effect (a util that
    // reads env is Env, a config loader that reads a file is Fs) — never a fabricated Log.
    //
    // This replaces an earlier whole-package gate + a growing per-type pure-accessor allowlist: a real
    // log4j-api scan showed the whole-package rule fabricated Log on ~100 non-Logger classes (and MASKED
    // their genuine Env/Fs). Verb-precise is the same narrowing the Rust classifier applies to
    // effect-bearing crates. SAFETY (no lost Log): every public emit entry point is named here, and
    // loggers reach the backend through these verbs, so Log still propagates through the call graph.
    static boolean isLogEmitVerb(String method) {
        switch (method) {
            // slf4j / log4j2 / logback shared level verbs + the generic log()
            case "trace": case "debug": case "info": case "warn": case "error":
            case "fatal": case "log":
            // jul level verbs + structured/localised emit
            case "severe": case "warning": case "config": case "fine": case "finer": case "finest":
            case "logp": case "logrb": case "entering": case "exiting":
            // throwable-logging emit (all four frameworks)
            case "catching": case "throwing":
            // log4j2 internal emit pipeline (public verbs delegate through these; named so Log propagates
            // even when the terminal append is out-of-jar) + fluent/structured entry points
            case "logIfEnabled": case "logMessage": case "printf": case "doLog": case "forcedLog":
            case "logEvent": case "traceEntry": case "traceExit":
            // backend append / publish (log4j-core Appender, jul Handler, logback Appender)
            case "doAppend": case "append": case "callAppenders": case "publish":
                return true;
            default:
                return false;
        }
    }


}
