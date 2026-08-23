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
    static final String SPEC_VERSION = "0.31";

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
    /** ⟨0.27⟩ SPEC §4 `zeroMatch` — the raw text of every policy rule whose SCOPE bound no function,
     *  recorded by {@link Policy#discloseZeroMatchRules} on BOTH gate routes and emitted onto the verdict
     *  document by {@link #writeGateJson}. The stderr lines alone left a machine consumer unable to see
     *  that a rule bound nothing — the typo'd-scope silent green, one channel over. Disclosure only:
     *  {@code ok} and the exit code never consult it. Cleared beside {@link #gateViolations}. */
    static final java.util.List<String> gateZeroMatch = new java.util.ArrayList<>();

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
        return runScan(target, null);
    }

    /** Guards {@link #enforceEnginePin} against saying the same thing once per {@code --parallel} target. */
    private static final java.util.Set<String> pinNoticesSaid = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * SPEC §3.4 {@code engine <version>} — the ENGINE↔BASELINE COUPLING, enforced instead of hoped for.
     *
     * <p><b>WHAT THIS ADDS, stated against what already existed — because the first draft of this comment
     * claimed more than was true.</b> {@link Policy}'s AS-EFF-005 path ALREADY refuses when the baseline's
     * producing build differs from the running one ("an engine swap is baseline-invalidating"), so it is
     * not the case that nothing enforced the coupling. What it cannot do is the part a consumer needs:
     *
     * <ul>
     *   <li>It compares the §2.1 provenance BUILD ID — a git hash like {@code b8589ac}. That is not
     *       something a human can pin, and there was nowhere to declare an intended version at all. The
     *       operator learns of a mismatch only after running the wrong engine.</li>
     *   <li>It lives INSIDE the baseline path, so a policy-only gate, or any scan with no {@code baseline}
     *       configured, has no coupling check whatsoever.</li>
     *   <li>It can only DETECT. A declared pin is also an instruction: {@code .candor/run} and the
     *       generated CI step read this same key to decide which engine to FETCH, which is what collapses
     *       the version to one place instead of restating it in CI YAML.</li>
     * </ul>
     *
     * The two are complementary and this one runs FIRST — at config load, before the scan — so a wrong
     * engine costs a message rather than a full analysis followed by a refusal.
     *
     * <p><b>Two of the five verdicts must not change the exit code</b>, and that is the whole design:
     * <ul>
     *   <li>{@code ABSENT} — no pin, or a pin naming another implementation. Today's behaviour, exactly.
     *       The feature is opt-in by construction: a config without an {@code engine} line is untouched.</li>
     *   <li>{@code UNDETERMINED} — the pin is well-formed and this build cannot state its own release,
     *       because the {@code build-info.properties} resource is absent (a repackaged jar, a classpath
     *       run without resources). The condition is UNANSWERABLE, and ⟨0.24⟩ §3.1's rule is that an
     *       unanswerable condition is DISCLOSED, never scored as a failed one — nor, which is the trap,
     *       as a satisfied one. So it says so, once, and does not touch the exit code.</li>
     * </ul>
     *
     * <p><b>A LIMITATION THIS CANNOT SEE, stated because an earlier draft claimed the opposite.</b>
     * {@code build.gradle.kts} bakes {@code release = project.version} into EVERY build, so a jar built
     * from an unreleased working tree reports the release version and MATCHes a pin naming it. The
     * comment here used to say a source build carries {@code unknown} and lands in UNDETERMINED; it does
     * not. The pin therefore distinguishes RELEASES, not builds — a developer's local jar, which may
     * resolve more dispatch than the released one, satisfies the pin for the whole inter-release window.
     * The §2.1 provenance build id (a git hash) is what separates those, and {@link Policy}'s AS-EFF-005
     * path already compares it against the baseline. The two checks answer different questions and the
     * pin is the coarser one.
     * A MISMATCH or a MALFORMED pin exits 2 (misconfiguration — the §3.4 fail-closed posture), not 1: the
     * run is UNEVALUABLE, not violating. A machine consumer distinguishing the two must not read
     * "I could not trust this result" as "your code broke a rule".
     */
    static void enforceEnginePin(Config cfg) {
        String pin = cfg.enginePinForThisEngine();
        String running = release();
        String where = cfg.source() != null ? cfg.source().toString() : ".candor/config";
        switch (Config.pinVerdict(pin, running)) {
            case ABSENT, MATCH -> { }
            case MALFORMED -> {
                System.err.println("candor: " + where + " has `engine " + pin + "`, which is not an engine version.");
                System.err.println("        want `engine <version>` (e.g. `engine v0.27.0`) or `engine <impl> <version>`");
                System.err.println("        (e.g. `engine java v0.27.0`) for a repo scanned by more than one engine.");
                System.err.println("        Failing (exit 2) rather than ignoring it: a pin that cannot be read is a");
                System.err.println("        guard the operator believes is on.");
                System.exit(2);
            }
            case MISMATCH -> {
                System.err.println("candor: " + where + " pins engine " + pin + " but this build is candor-java " + running + ".");
                System.err.println("        The pin and the committed baseline move together — a newer engine resolves more");
                System.err.println("        dispatch, so its report is not comparable with a baseline the pinned engine wrote.");
                System.err.println("        Either run the pinned engine, or update the pin and regenerate the baseline in the");
                System.err.println("        same change. Exit 2 (unevaluable), not 1 — this is not a policy violation.");
                System.exit(2);
            }
            case UNDETERMINED -> {
                if (pinNoticesSaid.add(where)) {
                    System.err.println("candor: " + where + " pins engine " + pin + ", and this build does not know its own");
                    System.err.println("        release version (a source build, not a published jar), so the pin CANNOT be");
                    System.err.println("        checked. Disclosed, not scored — neither passed nor failed. A released jar");
                    System.err.println("        enforces it.");
                }
            }
        }
    }

    /** {@link #runScan(Path)} with an EXPLICIT {@code .candor/config} layer instead of the process-wide
     *  {@link #config} static.
     *
     *  <p>{@code --parallel} scans N targets on N threads through one static, so it could not have a config
     *  per target and simply read whatever {@code config} held — which on that path is the
     *  {@code Config.empty()} default, because the only assignment to it lives on the single-target branch.
     *  Every `.candor/config` key was therefore silently dropped for every `--parallel` target, while the
     *  flag's own contract says each report is byte-identical to a standalone {@code candor <target>
     *  --json}. Measured: a project whose config names `deps` reported {@code app.A.run -> ['Unknown']}
     *  standalone and {@code []} under `--parallel`.
     *
     *  <p>The config rides the THREAD-LOCAL {@link AnalysisContext} rather than the static, so N concurrent
     *  targets each get their own — which is the reason a static could not simply be assigned in the task. */
    static Map<String, EffectSet> runScan(Path target, Config perScan) throws IOException {
        return runScan(target, perScan, false);
    }

    /** ⟨0.30⟩ {@link #runScan(Path, Config)} with the peek's VERSIONED file selection — see
     *  {@link AnalysisContext#peekVersioned}. The flag is applied after {@code resetState()} installs the
     *  fresh context and before {@code load()} reads anything, which is the only window where it can bind. */
    /** Everything a scan does BEFORE the per-class analyze loop: load, index, the whole-program
     *  pre-passes, the dependency join and the flags.
     *
     *  <p>Extracted so a measurement can drive the REAL preparation rather than a replica of it.
     *  RefreshBodyIndependenceTest needs a fully-prepared context in order to analyse one class against
     *  a program whose other bodies have been stripped, and a hand-rebuilt pipeline would answer a
     *  question about the replica instead of about the engine — it would drift, and it would drift
     *  silently, in a test whose whole job is to be trusted about staleness. */
    static List<ClassNode> prepareScan(Path target, Config perScan, boolean peekVersioned)
            throws IOException {
        resetState();
        ctx().peekVersioned = peekVersioned;
        Config cfg = perScan != null ? perScan : config;
        // ⟨0.19⟩/⟨0.20⟩ the gate-facing config maps, applied AFTER resetState (which installs the fresh
        // context) so they survive into the report + gate. main() also applies them from the static on the
        // single-target path; both are idempotent putAll/addAll into a just-created context.
        ctx().unknownAliases.putAll(cfg.unknownAliases());
        ctx().netPartners.addAll(cfg.netPartners());
        if (!cfg.netPartners().isEmpty() && cfg.source() != null)
            ctx().netPartnersSource = cfg.source().toString();   // ⟨0.31⟩ same object, so same file
        ctx().scanRoot = target;   // ⟨0.29⟩ so the scope block and the peek can name files as the operator does
        phase("start");
        List<ClassNode> classes = load(target);
        phase("load+parse");
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
        phase("index-methods");
        buildSubtypeIndex(classes);
        computeSpringTypes(classes);
        computeStreamFieldOrigins(classes); // VALUE-PROVENANCE Phase 2: which stream fields are provably all-concrete
        // Cross-jar inheritance (candor-spec §2): load dependency reports named by CANDOR_DEPS BEFORE
        // analyze, so a call into an already-analyzed dependency inherits its effects (vs assumed-pure).
        phase("subtype+spring+stream");
        loadCrossDeps(cfg.value("deps", "CANDOR_DEPS"), provenance()[0]);
        phase("cross-deps");
        ctx().taintEnabled = cfg.flag("taint", Mode.TAINT.envVar()); // read before analyze (the pass runs per method)
        ctx().closedWorld = forceClosedWorld || cfg.flag("closed-world", "CANDOR_CLOSED_WORLD"); // opt-in: scanned set is complete
        ctx().unknownRatchet = cfg.flag("unknown-ratchet", "CANDOR_UNKNOWN_RATCHET"); // opt-in: a NEW Unknown vs baseline fails
        // Per-class fail-soft: an exotic/malformed class that throws ANYWHERE in analyze (e.g. a malformed
        // method descriptor that ASM validates only lazily in Type.getArgumentTypes — the 0.5.6 crash class,
        // re-surfaced via an overloaded-name path the desc.startsWith("(") guard doesn't catch) must NOT
        // abort the WHOLE scan and silently zero EVERY other class's analysis (a DoS). Skip + disclose the
        // one bad class, mirroring collectClasses's tolerance.
        return classes;
    }

    static Map<String, EffectSet> runScan(Path target, Config perScan, boolean peekVersioned)
            throws IOException {
        List<ClassNode> classes = prepareScan(target, perScan, peekVersioned);
        Config cfg = perScan != null ? perScan : config;
        int analyzeSkipped = 0; String firstAnalyzeErr = null;
        // THE REFRESH SPLIT. Each class is analysed into an OVERLAY whose accumulators start empty, so
        // what it leaves behind is precisely that class's contribution, which is then folded into the
        // master. Run sequentially that is the same computation as writing into the master directly —
        // union is union, and the fold happens in the same class order — but it makes the per-class
        // delta a first-class object, and the delta is what a refresh caches and replays. See the
        // overlay section at the foot of AnalysisContext.
        //
        // ONE PATH, NOT TWO. It would be cheaper to build the overlay only when caching is switched on.
        // That is also how three of four engines end up correct and the fourth does not: the cached and
        // uncached routes would drift, and the drift would surface as a wrong report only for the people
        // using the cache. So the split runs always, and the cache decides one thing only — whether a
        // delta is computed or read back.
        AnalysisContext master = ctx();
        Refresh refresh = Refresh.forScan(cfg, classes);
        List<Integer> inputsBefore = Refresh.verifying() ? master.inputSizes() : null;
        for (ClassNode cn : classes) {
            try {
                AnalysisContext overlay = new AnalysisContext(master);
                AnalysisState.install(overlay);
                try {
                    if (!refresh.replayInto(cn, overlay)) analyze(cn);
                } finally {
                    AnalysisState.install(master);   // before the merge, and before any throw escapes
                }
                refresh.record(cn, overlay);
                overlay.mergeInto(master);
            } catch (Throwable t) {
                analyzeSkipped++;
                if (firstAnalyzeErr == null) firstAnalyzeErr = cn.name + ": " + t;
                // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): an un-analyzable class is unseen, not pure — disclose it
                // to a machine (report + gate verdict), so the gate fails closed rather than green over it.
                ctx().unanalyzed.put(cn.name, "class failed to analyze: " + t);
            }
        }
        if (inputsBefore != null) AnalysisContext.assertNoInputGrowth(inputsBefore, master.inputSizes());
        refresh.finish();
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

        phase("analyze+edges");
        classifySourceScope();
        phase("classify-scope");
        Map<String, EffectSet> fx = fixpoint();
        phase("fixpoint");
        return fx;
    }

    /** ⟨0.29⟩ WHICH JVM SOURCES UNDER THE SCAN ROOT HAVE NO COMPILED CLASS (candor-spec/FILE-SET-DESIGN.md).
     *
     *  <p>Runs here rather than in the walk because the question cannot be asked before there is an
     *  analyzed set. Called at the end of every {@link #runScan}, so the {@code --parallel} arm and a
     *  direct test call disclose the same scope as the single-target path — a per-arm disclosure is how
     *  three of four arms end up correct.
     *
     *  <p>THE JAVA ARM OF THE ⟨0.29⟩ MEASUREMENT. Pointed at a REPO ROOT under {@code deny Exec}, this
     *  engine reported `no violations`, exit 0, `analyzed {count: 3}` over a tree holding
     *  {@code src/com/x/Deploy.java} calling {@code Runtime.exec("curl … | sh")} — present, never
     *  compiled, so no class exists and nothing said so.
     *
     *  <p>UNCERTAINTY DISCLOSES. A source is called compiled only on a POSITIVE match against the analyzed
     *  class names, so a matching rule this misses over-reports the exclusion ("I did not read this")
     *  rather than under-reporting it. That is the denylist direction the family requires: an allowlist's
     *  omissions go silent, and a silent omission here is the claim that a file was judged when it was
     *  not. */
    static void classifySourceScope() {
        if (ctx().sourceFiles.isEmpty()) return;
        java.util.Set<String> compiled = new HashSet<>();
        for (String internal : ctx().projectClasses) {
            String dotted = internal.replace('/', '.');
            int nested = dotted.indexOf('$');   // an inner class is compiled FROM its outer's source file
            compiled.add(nested < 0 ? dotted : dotted.substring(0, nested));
        }
        for (String rec : ctx().sourceFiles) {
            int nul = rec.indexOf('\0');
            String path = rec.substring(0, nul).replace('\\', '/'), pkg = rec.substring(nul + 1);
            String file = path.substring(path.lastIndexOf('/') + 1);
            int dot = file.lastIndexOf('.');
            String stem = dot < 0 ? file : file.substring(0, dot);
            String qual = pkg.isEmpty() ? stem : pkg + "." + stem;
            // `FooKt` is Kotlin's file class for top-level declarations — a `.kt` whose only content is
            // top-level functions compiles to that name and to no class called `Foo` at all. Without this
            // arm every such file would be disclosed as never-compiled, and a disclosure that fires on
            // ordinary Kotlin is one an operator learns to ignore.
            boolean built = compiled.contains(qual) || compiled.contains(qual + "Kt");
            // ⟨0.29⟩ ONLY `.java` GUARANTEES filename == class name. That is a JAVA rule, not a JVM-language
            // one: a Kotlin file may declare `class Foo` in `Bar.kt` or several classes in one file, Scala
            // compiles a file to any number of classes plus `$` companions, and Groovy the same. So for
            // every other language the name test can only ever produce a FALSE "never compiled", which
            // would fire the operator-error nudge on ordinary, fully-compiled code — and a nudge that
            // fires on healthy projects is one people learn to scroll past, which costs the java arm the
            // only disclosure it has. Their PACKAGE is evidence enough: if this package produced classes,
            // the file was compiled by something, and this engine cannot say more than that honestly.
            if (!built && !path.endsWith(".java")) {
                String prefix = pkg.isEmpty() ? "" : pkg + ".";
                built = compiled.stream().anyMatch(c -> pkg.isEmpty() || c.startsWith(prefix));
            }
            if (!built && pkg.isEmpty()) {
                // No package declaration read (an unreadable head, or the default package): fall back to
                // the simple name anywhere. Widens what counts as compiled, which is the direction that
                // does not invent an exclusion.
                String suffix = "." + stem;
                built = compiled.stream().anyMatch(c -> c.equals(stem) || c.endsWith(suffix));
            }
            if (!built) ctx().excluded.put(path, "source-without-class");
        }
    }

    /** ⟨0.29⟩ WHY EACH EXCLUSION CLASS EXISTS, in the engine's own words, and whether THE PEEK reads it.
     *
     *  <p>The reason is a VALUE, not a presence: a consumer reads it to decide whether the exclusion
     *  matches the question they are asking, so conformance asserts on what it SAYS. Paraphrasing the
     *  rationale into something vaguer would defeat the block. */
    private static final Map<String, String[]> EXCLUDED_REASON = Map.of(
            "source-without-class", new String[]{"false",
                "candor-java reads BYTECODE, and these JVM sources have no compiled class under the "
                + "scanned path — so nothing in them was judged, and the peek cannot read them either. "
                + "This is not a scope decision like a build script's: it usually means the scan was "
                + "pointed at a repo root instead of compiled output. Build the project and scan "
                + "target/classes · build/classes/java/main, or a built .jar."},
            "archive-under-the-scan-root", new String[]{"true",
                "a `.jar`/`.zip` under the scan root is bytecode this engine reads perfectly well, and a "
                + "directory walk looking for `.class` files never opens it. The gate did not judge its "
                + "contents; the peek reads them."},
            "build-output-archive", new String[]{"false",
                "a `.jar`/`.zip` under build/ · target/ · out/ · .gradle/ · node_modules/ is DERIVED "
                + "output — its contents come from the sources this gate already judges, so the peek "
                + "does not read it. MEASURED on this engine's own repo: peeking them charged one "
                + "dependency class six times, once per fat jar in build/libs, beside the single real "
                + "finding. Point the scan into the build tree and these are ordinary archives again."},
            "archive-inside-the-archive", new String[]{"false",
                "a `.jar`/`.zip` nested inside the archive being scanned. The outer archive is mounted as "
                + "a zip filesystem and closed when the walk ends, so a nested entry cannot be reopened "
                + "afterwards and the peek does not read it. Scan the nested jar directly, or scan the "
                + "exploded directory, to judge its contents."},
            "multi-release-override", new String[]{"true",
                "a multi-release jar ships version-specific overrides under META-INF/versions/<N>/. The "
                + "BASE class of each is analyzed (the portable surface) and the override is not, so an "
                + "effect present ONLY in a versioned copy is outside this verdict — and the versioned "
                + "copy is the one a JVM of that version actually runs. ⟨0.30⟩ the peek READS the "
                + "overrides and reports what it finds; the flag here says whether every one of them was "
                + "read on THIS run."});

    /** ⟨0.30⟩ What the DENY rules charge this peeked function — the same decision {@link Policy}'s
     *  AS-EFF-006 arm makes for a judged one: scope test per rule, then `pure` (empty effects) means
     *  every effect EXCEPT Unknown, and a named rule means the intersection. Shared rather than
     *  re-derived because §6.2 requires the gate and the disclosure to apply the same rule, and the flat
     *  effect-name set this replaced was wrong in both directions (see the call site). */
    private static List<String> peekHits(List<PolicyRule.Deny> rules, String fn, EffectSet inferred,
                                        Policy.GateInput gi) {
        EffectSet bad = EffectSet.empty();
        for (PolicyRule.Deny r : rules) {
            if (!Policy.scopeMatches(fn, r.scope())) continue;
            EffectSet h = r.effects().isEmpty()
                    ? inferred.without(Effect.UNKNOWN)
                    : inferred.intersect(r.effects());
            // ⟨0.30⟩ …AND THE RULE'S CLASS NARROWING, through the SHARED §6.2 definition the gate uses.
            // Without it the peek charged the whole effect for a rule that denies ONE class: MEASURED,
            // `deny Net[unknown-host]` reddened a DECLARED partner and `deny Net[known-partner]` reddened
            // with no partners configured, while the identical code IN SCOPE passed both. The same defect
            // was closed in ts and rust a round earlier and the hand-port missed it here — which is what
            // the generated policy matrix exists to catch, and did.
            for (Effect w : List.of(Effect.UNKNOWN, Effect.NET))
                if (h.contains(w) && !Policy.classNarrowingFires(r, gi, fn, w))
                    h = h.without(w);
            bad = bad.join(h);
        }
        return bad.toNames();
    }

    /** ⟨0.29⟩ THE PEEK — read the files this scan deliberately did NOT judge, and say so when they hold an
     *  effect the policy DENIES (candor-spec/FILE-SET-DESIGN.md §5.2, rung 2 of the ladder).
     *
     *  <p>⟨0.30⟩ THE VERDICT GOES INCOMPLETE. The findings ride the report as {@code outOfScope}, their
     *  own kind, and are never {@code violations} — the gate did not JUDGE these units, so a violation
     *  claim would be false in the other direction. A non-empty block makes the verdict
     *  {@code ok:false, incomplete:true} at exit 2: "I could not see enough of this tree to answer",
     *  which is what happened. ⟨0.29⟩ required the exit code to stay put; that was reversed on the
     *  measurement that the peek resolves a CONCRETE denied effect rather than uncertainty.
     *
     *  <p>A RECURSIVE {@link #runScan} over the archive, not a hand-written second pass. {@code load()}
     *  already reads a jar — it is the same entry point, the same ASM parse, the same classifier, over a
     *  different file. That identity is the design constraint and not a convenience: a bespoke walk would
     *  be a SECOND OPINION, and a drifted second opinion reported as a warning is worse than no warning,
     *  because the reader cannot tell a real finding from two code paths disagreeing.
     *
     *  <p>ON A THREAD, because {@code runScan} calls {@code resetState()} and {@link AnalysisState#ctx()}
     *  is thread-local: peeking on the calling thread would destroy the analysis whose report this is
     *  about to join. The thread is this engine's existing isolation mechanism — {@code --parallel} scans
     *  N targets the same way — so the peek needs no new one.
     *
     *  <p>POLICY-SCOPED AND POLICY-BOUNDED, which is what keeps it quiet: no policy ⇒ no peek and NO KEY,
     *  because nothing was asked and {@code []} would be a claim; with one, only effects that policy
     *  DENIES are reported, so the noise floor is "things you have already said you care about" rather
     *  than "everything in the jars under your repo".
     *
     *  <p>AND NEVER A FUNCTION THE GATE ALREADY JUDGED. A repo root commonly holds both
     *  {@code build/classes} and {@code build/libs/app.jar} — the same code twice — so without this filter
     *  the peek would report every effect in the project as out-of-scope while the gate was judging it.
     *  "The gate did not judge this" is a claim, and it is false for any qual already in the analyzed set. */
    static void peekExcluded(String policyPath) {
        if (policyPath == null || policyPath.isEmpty()) return;   // nothing asked, so nothing claimed
        List<Report.OutOfScope> found = new ArrayList<>();
        // ANSWERED, not "a policy was configured". A policy this engine REFUSES — unreadable, or naming a
        // token it does not know — is a policy the gate evaluates nothing under, and `outOfScope: []`
        // beside a refusal would certify a look that never happened. §3.1's answerability MUST binds every
        // producer reading the policy, not the gate alone, so the key stays ABSENT unless the parse stood.
        boolean[] answered = {false};
        int[] peekFailures = {0};
        int[] peekPartial = {0};
        boolean[] peekReadAll = {false};
        boolean[] peekVersionedAll = {false};   // ⟨0.30⟩ the multi-release pass's own read result
        // ⟨0.30⟩ read on the CALLING thread, before the peek thread's resetState: the peek must classify
        // destinations against the same `net-partner` set the gate uses.
        final Config peekConfig = config;
        boolean[] timedOut = {false};
        List<Path> archives = List.copyOf(ctx().archives);
        Set<String> judged = Set.copyOf(ctx().edges.keySet());
        Path root = ctx().scanRoot;
        // The peek's own stderr is DISCARDED for its duration. It parses the policy (to learn what is
        // denied) and scans jars, and both are chatty — an ignored-policy-line warning printed once by the
        // peek and again by the gate reads as two problems, and a jar's unparseable-class notice is about
        // a file set the operator did not ask about. Restored in the finally, before any gate output.
        PrintStream saved = System.err;
        try {
            System.setErr(new PrintStream(java.io.OutputStream.nullOutputStream()));
            Thread t = new Thread(() -> {
                // THE SAME PARSER THE GATE USES, over the same bytes — one extra read, not a second
                // interpretation of the grammar. It runs on this thread because `parsePolicy` fills the
                // THREAD-LOCAL ctx().denyRules, and a parse on the main thread would leave the gate's own
                // parse appending to a list that already held these rules.
                if (!Policy.parsePolicy(policyPath)) return;   // unreadable/erroring — the GATE's refusal to make
                answered[0] = true;
                // ⟨0.30⟩ THE TRIGGER IS "ARE THERE DENY RULES", and the charge below is the GATE'S OWN
                // decision, per (rule, function). This built a flat set of effect NAMES and returned when
                // it was empty — which §6.2 already forbids ("THE GATE AND THE DISCLOSURE MUST APPLY THE
                // SAME RULE, AND SHOULD SHARE THE SAME CODE") and which was wrong BOTH ways once ⟨0.30⟩
                // made the block verdict-bearing. Both MEASURED four-way in review:
                //
                //   UNDER-REPORT: `pure` is a deny rule with an EMPTY effect list meaning "every effect
                //   except Unknown" (see Policy's AS-EFF-006 loop). Flattened it named NOTHING, so this
                //   returned early and the STRICTEST policy silently disarmed the peek — exit 0 where the
                //   weaker `deny Exec` exits 2 on the same tree. A four-way false all-clear, and the old
                //   comment here ("`pure`/allow-only: nothing named, so nothing to look for") documented
                //   it as intended.
                //
                //   OVER-CHARGE: a `deny Net[known-partner]` denies ONE destination class, but the name
                //   set held bare `Net`, so a peeked fn reaching an unknown host — which that rule does
                //   not deny — turned the verdict red while the same code in scope passed. Rule SCOPES
                //   were dropped the same way.
                List<PolicyRule.Deny> peekRules = List.copyOf(ctx().denyRules);
                if (peekRules.isEmpty()) return;   // allow-only: nothing denied, so nothing to look for
                int[] readOk = {0}, readFail = {0}, readPartial = {0};
                for (Path jar : archives) {
                    Map<String, EffectSet> peeked;
                    try {
                        // Read BEFORE runScan's resetState wipes this thread's context: `denied` is already
                        // a local, which is the whole reason it is one.
                        // ⟨0.30⟩ THE PROJECT'S CONFIG, not an empty one. `Config.empty()` left the peek
                        // with no `net-partner` set, so every host classified as unknown-host and the
                        // rule's class narrowing answered against a set that was always empty —
                        // MEASURED: `deny Net[known-partner]` MISSED a declared partner (a false
                        // all-clear) while `deny Net[unknown-host]` reddened that same partner. The
                        // config is what the gate reads; the peek is the same rule over a different file
                        // set, so it must read it too. (candor-ts had this exact defect via its child
                        // process; found there first, then here by the generated matrix.)
                        peeked = runScan(jar, peekConfig);
                    } catch (Throwable e) {
                        // A PEEK THAT CANNOT RUN MUST NOT FAIL THE GATE — it is advisory by construction,
                        // and turning an unreadable jar into a red gate would make adding a policy, the
                        // safest thing an operator can do, the thing that breaks their build.
                        //
                        // ⟨0.29⟩ …BUT IT MUST NOT PASS FOR ONE EITHER. This was a bare `continue`, so a
                        // jar that could not be opened was indistinguishable from a jar that was read and
                        // held nothing — and `peeked:true` shipped over both. Counted now, and the count
                        // decides the flag below.
                        readFail[0]++;
                        continue;
                    }
                    readOk[0]++;
                    // ⟨0.30⟩ the peek thread's OWN derived classes, built right after its runScan while
                    // that context is still current — the same shape the scan gate builds for itself.
                    Policy.GateInput peekGi = Policy.gateInputFromScan(peeked);
                    // ⟨0.29⟩ OPENING THE ARCHIVE IS NOT READING IT. `runScan` records every class it could
                    // not analyze in this thread's `unanalyzed` (the ⟨0.21⟩ completeness manifest), and it
                    // was thrown away — so a jar that opened fine and whose classes failed to analyze was
                    // indistinguishable from one read cover to cover, and `peeked: true` shipped over both.
                    // Exactly the distinction the `catch` above already draws one level out; a partial read
                    // is the same overclaim as no read at all (⟨0.26⟩). `newContext()` gives each `runScan`
                    // a clean slate, so this is THIS jar's count and no other's.
                    if (!ctx().unanalyzed.isEmpty()) readPartial[0]++;
                    String where = root == null ? jar.toString() : relativeTo(root, jar);
                    for (var e : new java.util.TreeMap<>(peeked).entrySet()) {
                        if (judged.contains(e.getKey())) continue;   // the gate DID judge this one
                        List<String> hits = peekHits(peekRules, e.getKey(), e.getValue(), peekGi);
                        if (hits.isEmpty()) continue;
                        found.add(new Report.OutOfScope(e.getKey(), where, hits,
                                "archive-under-the-scan-root",
                                "OUTSIDE this scan's scope (archive-under-the-scan-root) — the gate did "
                                + "NOT judge it. candor's ANALYSIS of that file reaches this effect, "
                                + "so the verdict is INCOMPLETE rather than a pass (an analysis result, "
                                + "not a claim about what the code does at runtime)."));
                    }
                }
                // ⟨0.30⟩ THE MULTI-RELEASE PASS. A multi-release jar ships version-specific overrides under
                // META-INF/versions/<N>/; the ordinary scan analyses the BASE class and skips the override,
                // so an effect present ONLY in a versioned copy sat outside every verdict. That exclusion
                // declared itself `peeked: false` and said exactly this in its own reason — an honest
                // hole, and one this engine can close, because a versioned override IS bytecode and
                // `load()` already reads it.
                //
                // MEASURED on log4j-api 2.23.1 before this pass existed: scanning the BASE copies against
                // the base-with-overrides-applied — which is what any JVM 9+ actually runs — gave 21
                // functions a materially different verdict and left 5 that exist ONLY in the versioned
                // copy unjudged. On that jar the divergence is over-statement, but the mechanism is
                // symmetric: an override may ADD an effect the base does not have.
                //
                // THE TARGET ITSELF IS INCLUDED, not just nested archives — the log4j case IS the target.
                // `runScan(…, true)` inverts the file selection rather than walking a second way, so this
                // is the same parse and the same classifier over a different file set (§2's MUST).
                int[] vOk = {0}, vFail = {0}, vPartial = {0};
                List<Path> versionedTargets = new ArrayList<>(archives);
                if (root != null && !versionedTargets.contains(root)) versionedTargets.add(root);
                for (Path jar : versionedTargets) {
                    Map<String, EffectSet> over;
                    try {
                        over = runScan(jar, peekConfig, true);
                    } catch (Throwable e) {
                        vFail[0]++;
                        continue;
                    }
                    // ⟨0.30⟩ THE PARTIAL-READ CHECK COMES FIRST, and the order is the whole of it. This read
                    // `if (over.isEmpty()) continue;` BEFORE asking whether anything failed to parse, so a
                    // jar whose versioned copies ALL fail to parse was indistinguishable from one with
                    // none — and the class then shipped `peeked: true` beside `outOfScope: []`, which is
                    // the sentence "I read every override and none performs a denied effect" over an
                    // override nobody read. MEASURED: a versioned copy at bytecode major 99 (the case this
                    // exclusion's own comment warned about) performing Exec answered exit 0, `peeked:true`,
                    // `outOfScope:[]` under `deny Exec`. A false all-clear inside the pass that closes
                    // false all-clears.
                    // COUNT THE PARTIAL READ, DO NOT SKIP THE FINDINGS. The `continue` here was itself a
                    // false all-clear, and a trivially triggerable one: ONE unreadable `.class` anywhere
                    // under META-INF/versions/ suppressed the findings from every override that DID read.
                    // MEASURED — a multi-release jar whose versioned copy performs `Exec` answers exit 2
                    // under `deny Exec`; add a single junk file beside it and the same jar answers exit 0
                    // with `outOfScope: []` and no disclosure on any channel. Introduced while fixing the
                    // ORDERING defect above, which is the shape this project keeps measuring: the repair
                    // for one false all-clear opening the next.
                    //
                    // The two facts are INDEPENDENT and both must travel: an unreadable file withdraws the
                    // `peeked` claim for the class (⟨0.29⟩ PART 52), and what WAS read is still evidence.
                    if (!ctx().unanalyzed.isEmpty()) vPartial[0]++;
                    if (over.isEmpty()) continue;          // genuinely no versioned entries — not a failure
                    vOk[0]++;
                    Policy.GateInput peekGi = Policy.gateInputFromScan(over);
                    String where = root == null ? jar.toString() : relativeTo(root, jar);
                    for (var e : new java.util.TreeMap<>(over).entrySet()) {
                        // NOT filtered by `judged`: the base copy of the SAME qualified name is judged, and
                        // that is exactly the case this pass exists for — the override is different code
                        // under the same name, and skipping it because the base was judged would silently
                        // drop every finding this pass can make.
                        List<String> hits = peekHits(peekRules, e.getKey(), e.getValue(), peekGi);
                        if (hits.isEmpty()) continue;
                        found.add(new Report.OutOfScope(e.getKey(), where, hits,
                                "multi-release-override",
                                "OUTSIDE this scan's scope (multi-release-override) — the gate judged the "
                                + "BASE class and did NOT judge this versioned override, which is the copy "
                                + "a JVM of that version actually runs."));
                    }
                }
                peekVersionedAll[0] = vFail[0] == 0 && vPartial[0] == 0;

                // ⟨0.29⟩ THE CLASS IS `peeked` ONLY IF EVERY FILE OF IT WAS READ. One unreadable jar means
                // the class was not fully examined, and a partial read publishing `peeked:true` is the
                // same overclaim as no read at all — ⟨0.26⟩'s rule that a partial manifest answers worse
                // than an absent one.
                //
                // RECORDED IN THE CAPTURED ARRAYS, NOT IN `ctx()`. This thread has its OWN thread-local
                // context — that is the entire reason the peek runs on a thread — so writing the result
                // through `ctx()` here files it against a context nobody reads and the flag stays false
                // on every run. Caught by the flag reading `false` on a peek that had just produced a
                // finding, which is the one observation that separates the two.
                peekReadAll[0] = readOk[0] > 0 && readFail[0] == 0 && readPartial[0] == 0;
                peekFailures[0] = readFail[0];
                peekPartial[0] = readPartial[0];
            }, "candor-peek");
            t.start();
            // ⟨0.29⟩ A DEADLINE, because the peek re-parses exactly the bytecode this engine has never
            // parsed — a vendored jar, a shaded artifact, whatever sat under the scan root — i.e. the
            // inputs least likely to have been exercised. An unbounded join turns one pathological
            // archive into a hung SCAN and a hung CI job, with `System.err` pointed at the null stream for
            // the whole window so it hangs SILENTLY. That contradicts this feature's own rule that a peek
            // which cannot run must not fail the gate: hanging is the one failure that stops the gate
            // completing at all.
            t.join(120_000);
            if (t.isAlive()) {
                // The thread is left to die with the process rather than stopped — `Thread.stop` is
                // unsafe and there is nothing here worth an interrupt protocol. What matters is that this
                // thread stops WAITING, and that nothing downstream claims the peek read anything: the
                // `peekReadAll` flag is still false, so every class stays `peeked: false`.
                timedOut[0] = true;
                return;
            }
        } catch (InterruptedException e) {
            // ⟨0.29⟩ RETURN, do not fall through. This caught the interrupt and carried on to publish
            // `found` while the peek thread was still alive and still appending to it — a live data race
            // on a list the report is about to serialize. An interrupted wait means the answer is not
            // ready, which is exactly the case the `answered` flag exists to express.
            Thread.currentThread().interrupt();
            return;
        } finally {
            System.setErr(saved);
        }
        if (timedOut[0]) {
            System.err.println("candor-java: the peek did not finish within 120s and was abandoned — "
                    + "`excluded` marks its classes NOT peeked, so nothing claims they were read. "
                    + "The gate below is unaffected.");
            return;
        }
        if (!answered[0]) return;   // the policy did not stand — see `answered`
        ctx().outOfScope = found;
        // …applied HERE, on the MAIN thread, whose context is the one the report is written from.
        if (peekReadAll[0]) ctx().peekedClasses.add("archive-under-the-scan-root");
        // ⟨0.30⟩ …and the versioned class, on the same rule: `peeked: true` means every file of it was
        // READ on this run, so one unreadable or partially-analysed override withdraws the claim for the
        // whole class (⟨0.29⟩ PART 52).
        if (peekVersionedAll[0]) ctx().peekedClasses.add("multi-release-override");
        if (peekFailures[0] > 0) {
            System.err.println("candor-java: " + peekFailures[0] + " archive(s) under the scan root could "
                    + "not be opened for the peek — they are counted in `excluded` and their class is "
                    + "marked `peeked: false`, so the empty `outOfScope` below makes no claim about them.");
        }
        if (peekPartial[0] > 0) {
            System.err.println("candor-java: " + peekPartial[0] + " archive(s) opened for the peek held "
                    + "class(es) that could not be analyzed — the class is marked `peeked: false`, so the "
                    + "`outOfScope` below makes no claim about what those classes do.");
        }
        // SAY IT ON STDERR, ABOVE THE VERDICT. The report block is for machines; an operator reading
        // `no violations` needs to know in the same breath that a file this scan did not judge holds the
        // effect they denied. A caveat printed below a green verdict is a caveat nobody reaches.
        for (Report.OutOfScope f : found) {
            System.err.println("candor-java: ⚠ " + f.fn() + " performs " + String.join("+", f.effects())
                    + " — OUTSIDE this scan's scope (" + f.cls() + "), so the gate did NOT judge it.");
            System.err.println("             " + f.path());
        }
        if (!found.isEmpty()) {
            System.err.println("             The verdict below does not account for "
                    + (found.size() == 1 ? "it." : "these " + found.size() + "."));
        }
    }

    /** A scan-root-relative path for a disclosure — an absolute path names the CI runner's checkout. */
    private static String relativeTo(Path root, Path p) {
        try {
            return root.relativize(p).toString();
        } catch (IllegalArgumentException e) {
            return p.toString();
        }
    }

    /** ⟨0.29⟩ The scope block for the report: one entry per class, with its count and reason. ALWAYS
     *  returns a list — `[]` is the positive statement "I looked and excluded nothing" (⟨0.27⟩), and an
     *  absent key would mean "this producer cannot answer" (⟨0.26⟩). */
    /** ⟨0.32⟩ THE EXCLUSION CLASSES THAT DO NOT HIDE UNJUDGED CODE — the carve-out for the
     *  incomplete-verdict rule, and a DENYLIST on purpose.
     *
     *  <p>`peeked: false` is nearly the right discriminator: it is this engine saying it did not open
     *  those files. But one class is unread precisely BECAUSE its contents were already judged —
     *  `build-output-archive` is a jar under build/ · target/ · out/, i.e. a DERIVED copy of the classes
     *  the scan just analysed. Failing a gate on it would redden every project that builds a jar, over
     *  code that was in fact judged.
     *
     *  <p>Stated as what is proven SAFE to skip rather than as what must fail: an allowlist of
     *  "classes that fail closed" under-reports whatever nobody thought of, and what nobody thought of
     *  is exactly the unjudged code this rule exists to catch. A new exclusion class therefore fails
     *  CLOSED by default and someone has to argue it onto this list. */
    static final Set<String> DERIVED_EXCLUSIONS = Set.of("build-output-archive");

    static List<Report.ExcludedClass> excludedClasses() {
        Map<String, Integer> byClass = new java.util.TreeMap<>();
        for (String cls : ctx().excluded.values()) byClass.merge(cls, 1, Integer::sum);
        List<Report.ExcludedClass> out = new ArrayList<>();
        for (var e : byClass.entrySet()) {
            String[] r = EXCLUDED_REASON.getOrDefault(e.getKey(), new String[]{"false", "excluded (" + e.getKey() + ")"});
            // ⟨0.29⟩ `peeked` IS AN OUTCOME, NOT A PROPERTY OF THE CLASS. It was read out of the table
            // beside the reason, so a peek that never ran — no policy, no denied effect — or one whose
            // every jar failed to open still published `peeked: true` beside `outOfScope: []`, which is
            // byte-identical to a clean peek. That is the ⟨0.26⟩ partial-manifest failure inside the rung
            // built to prevent it: this flag exists so `[]` cannot overclaim, and a lookup table cannot
            // do that job. A class is `peeked` only if this run actually READ a file of it.
            boolean peeked = Boolean.parseBoolean(r[0]) && ctx().peekedClasses.contains(e.getKey());
            // ⟨0.32⟩ THIS engine knows which of its own exclusions are derived duplicates; it says so in
            // the report rather than leaving each consumer to guess from a token it does not own.
            out.add(new Report.ExcludedClass(e.getKey(), e.getValue(), peeked,
                    DERIVED_EXCLUSIONS.contains(e.getKey()), r[1]));
        }
        return out;
    }

    /// Set by any site that has ALREADY reported a truncated stdout, so the shutdown hook below does not
    /// say it twice with less detail.
    private static boolean stdoutLossReported = false;

    public static void main(String[] args) throws IOException {
        // ── ONE CHECK AT EXIT, COVERING ALL ~148 `System.out` SITES ──────────────────────────────────
        // `PrintStream` swallows `IOException` — documented behaviour — and its internal error flag
        // LATCHES: once a write fails, `checkError()` stays true for the life of the stream. So a single
        // check on the way out catches a failed write ANYWHERE in the run, which is the only tractable
        // shape here; guarding 148 call sites individually is how 147 of them would end up unguarded.
        //
        // MEASURED, inside Linux against a 4096-byte pipe (F_SETPIPE_SZ) whose reader closes mid-write:
        // candor-java exited 0 with an EMPTY stderr while candor-ts on the identical setup reported
        // "output was cut short at 4096 of 24110 bytes". A machine consumer read a fraction of the
        // document and had nothing to tell it apart from a complete one. Before this change there were
        // ZERO `checkError` calls in src/main.
        //
        // EXIT 0 IS KEPT. `candor-java … | head` must not be a failure, and the ruling is candor-ts's:
        // the reader leaving is not our error, but the truncation has to be STATED. A shutdown hook
        // rather than a wrapper because this class exits through `System.exit` from many branches.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.flush();
            if (System.out.checkError() && !stdoutLossReported) {
                System.err.println("candor-java: stdout reported a WRITE ERROR — the output above is "
                        + "INCOMPLETE (the reader closed the pipe, or the sink failed). Re-run to a file "
                        + "if you need the whole document.");
            }
        }));
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>] [--policy <file>] [--gate-json <file>]");
            System.err.println(
                    "       candor <show|where|callers|map|diff|containment|reachable|path|impact|blindspots|tour|gains|whatif|rewire> [args] [--report <locator>]");
            System.err.println("       candor gate --report <locator> --policy <file> [--json] [--gate-json <file>]");
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
        //
        // §3.3: this summary lists every flag the parser ACCEPTS. Two omissions, measured by the P8
        // sink-surface matrix 2026-08-12: the `verify` verb — a whole value-taking flag family
        // (--run/--report/--scope) reachable from argv but absent from this text — and `--class`,
        // which the query loop accepts on every action (refusing it a value like any real flag)
        // while only this text's silence said otherwise. An undocumented accepted flag is a small
        // instance of the thing this project exists to catch. `--class` is DOCUMENTED rather than
        // rejected on the actions that ignore it: measured the same day, candor-rust and candor-ts
        // both run `tour --class dynamic` to exit 0 (the shared-grammar posture) and document the
        // flag — rejecting here would split the family in the other direction.
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
                      candor verify [<classes-or-jar>] --run "<cmd>" [--report <json>] [--scope direct|all]
                                                                run the program under this jar's recording agent
                                                                and check the report's claims against the observed
                                                                effect trace — the dynamic honesty oracle (exit 1
                                                                on a divergence; `candor verify --help` for detail)
                      candor parsepolicy <policy-file>          print a parsed policy file as canonical JSON

                    COMMON ACTIONS
                      where <Effect>            the functions that perform an effect
                      path <fn> <Effect>        the call path by which a function reaches an effect
                      callers <fn>              who calls a function, direct and transitive
                      tour [N]                  the N most surprising transitive reaches (default 10)
                      blindspots                the Unknown sources worth resolving, ranked by reach
                      gains <current> <base>    what a new version newly reaches (the supply-chain diff)
                      fix <fn> <Effect>         the boundary hoist that would clear a violation
                      gate --policy <file>      apply a policy to an EXISTING report, with no scan —
                                                the supply-chain gate (exit 1 on a violation, 2 if the
                                                policy or the report cannot be read). Same exit codes and
                                                same verdict shape as `candor <classes> --policy <file>`;
                                                the only difference is that the effect set is READ from
                                                the report rather than recomputed from bytecode.

                    ALL ACTIONS
                      show  where  callers  map  containment  diff  reachable  impact  blindspots
                      gains  path  tour  whatif  fix  fix-gate  unverified  rewire  gate  parsepolicy

                    OPTIONS  (uniform across every engine)
                      --report <locator>        use this report instead of discovering .candor/
                      --policy <file>           enforce a policy file (deny/pure/allow/forbid) — exit 1
                                                on a violation, 2 if unreadable; honours $CANDOR_POLICY
                                                when the flag is absent
                      --class <c,…>             blindspots/unverified: drill down by Unknown reason class
                                                (SPEC §6.2 ⟨0.24⟩) — ONE comma-separated list, accepted on
                                                every action, not repeatable
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
                                                `engine v0.27.0` pins the engine this repo's baseline was
                                                generated with — a different build exits 2 rather than
                                                comparing a report against a baseline it cannot match

                    Docs: candor.poly.io   ·   Verify an install: candor doctor""");
            System.exit(0);
        }
        if (args[0].equals("--agents")) {
            try (var in = Candor.class.getResourceAsStream("/AGENTS.md")) {
                if (in == null) {
                    System.err.println("candor: the AGENTS.md resource is missing from this build");
                    System.exit(2);
                }
                byte[] doc = in.readAllBytes();
                System.out.println("<!-- candor-java " + provenance()[0]
                        + " · the agent contract for this installed version -->");
                System.out.write(doc);
                System.out.flush();
                // checkError(), because PrintStream SWALLOWS IOException — that is its documented
                // behaviour, and it is why this path could truncate in total silence. MEASURED inside
                // Linux against a 4096-byte pipe (F_SETPIPE_SZ) with a reader that closes mid-write:
                // candor-java exited 0 with an EMPTY stderr, while candor-ts on the identical setup said
                // "--agents output was cut short at 4096 of 24110 bytes". An agent piping this into its
                // context read a fraction of its own instructions and had no way to know — the cardinal
                // sin on the documentation channel. There are zero other checkError calls in src/main.
                //
                // EXIT 0 IS KEPT DELIBERATELY. `candor-java --agents | head` is a legitimate thing to
                // type and must not be a failure; candor-ts made the same ruling for the same reason.
                // The reader leaving is not our error — but a truncated contract with exit 0 and an
                // empty stderr is exactly the defect, so the truncation is STATED. stderr may be closed
                // for the same reason stdout is, so this is best-effort by construction.
                if (System.out.checkError()) {
                    stdoutLossReported = true;
                    System.err.println("candor-java: --agents output was cut short (the reader closed the "
                            + "pipe, or the write failed). This contract is INCOMPLETE — " + doc.length
                            + " bytes were offered and an unknown number arrived.");
                }
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
        // artifacts). Each report is byte-identical to a standalone `candor <target> --json` of that target
        // — including its `.candor/config`, which each task resolves for ITS OWN target and passes into
        // runScan. That promise was false until then: `config` is a process-wide static assigned only on
        // the single-target branch, so every `--parallel` target scanned with `Config.empty()` and a
        // checked-in `deps`/`taint`/`net-partner` key was silently dropped. A config that names a dep
        // report is the consequential one — the effects it chains simply did not arrive, and the report
        // read cleaner than the standalone run of the same bytes.
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
                        Config perTarget = Config.forTarget(t);
                        // Each --parallel target resolves its OWN config, so each carries its own pin. The
                        // check runs per target for the same reason the config load does; the disclosure
                        // path dedups so N targets under one repo root say it once, and the failure path
                        // exits the process, which is right — a broken engine↔baseline coupling is not a
                        // per-target result to be collected and summarised.
                        enforceEnginePin(perTarget);
                        writeReport(runScan(t, perTarget), out.toString(), null);  // own thread → own ctx() + own config (LB-1b)
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
            ctx().onlyRules.clear();   // ⟨0.29⟩ same reason as its siblings — a stale rule gates the next policy
            // ⟨0.19⟩ config-aware: discover `.candor/config` (or CANDOR_CONFIG) anchored to the policy file so
            // an `Unknown[<alias>]` resolves via a checked-in `unknown-alias` — the dump reflects real gate
            // resolution (and the four-way parsepolicy differential pins the expansion).
            Config pcfg = Config.policyVocabulary(Path.of(args[1]));   // ⟨0.24⟩ the named anchor (§3.1)
            ctx().unknownAliases.putAll(pcfg.unknownAliases());
            ctx().netPartners.addAll(pcfg.netPartners());
        if (!pcfg.netPartners().isEmpty() && pcfg.source() != null)
            ctx().netPartnersSource = pcfg.source().toString();   // ⟨0.31⟩ same object, so same file
            // ⟨0.24⟩ SPEC §3.1 — **THE WITNESS MUST NOT REFUSE.** An unrecognised class token is a policy
            // error at the GATE (§6.2, exit 2, policy NOT evaluated) — but the gate is the thing that must
            // not enforce a policy it cannot honour, and this verb is not the gate. Its whole job is to
            // answer *what did this engine make of my policy?*, which is most valuable exactly when the
            // answer is "not what you meant". Refusing here made the four-way PART 4 differential HALT on a
            // battery that carries such tokens deliberately, so one ruling took the differential offline at
            // the one input where the engines are likeliest to differ. So: report the parse AND the errors,
            // exit 0. An unreadable FILE still exits 2 — there is no parse to report.
            if (!parsePolicy(args[1]) && Policy.policyUnreadable) {
                System.err.println("candor: " + Policy.policyFailure(args[1])); System.exit(2);
            }
            // …and say so on stderr too, so a human reading `parsepolicy` does not take exit 0 for a green
            // light: this verb's 0 means "here is the parse", never "this policy will run".
            // FATAL entries only. A DROPPED line already printed its own "ignoring policy rule" warning as
            // the parser threw it away, and it does NOT make the gate refuse (§3.1 195d45a is additive to
            // the witness and deliberately silent about the gate) — so repeating this sentence over it
            // would be a FALSE disclosure, the class PART 13b exists for.
            for (var e : Policy.policyErrors)
                if (e.fatal())
                    System.err.println("candor parsepolicy: " + e.message() + " — in policy rule: " + e.rule()
                            + "\n        Reported in `errors` and NOT applied; the GATE REFUSES this policy (exit 2).");
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
            // The ⟨0.28⟩ value-shape rule reaches this harness verb too: a flag-shaped token after
            // `--json` is not a filename, so it is skipped and rj stays null → the usage error below.
            for (int i = 3; i < args.length; i++)
                if (args[i].equals("--json") && i + 1 < args.length && !args[i + 1].startsWith("-")) rj = args[++i];
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
        String jsonOut = null, policyArg = null, gateJson = null;
        // ── SPEC §3.3.1 ⟨0.27⟩ ARM FIRST. This pre-pass learns the sink and the run's inputs with NO side
        // effects, so that (a) the collision check can run before anything is written, and (b) arming
        // happens before EVERY other exit — including an unknown flag, which §3.3 names as a broken-gate-
        // config exit-2 cause that must leave a refusal.
        //
        // Arming used to happen INSIDE the loop below, at the moment `--gate-json` was parsed. That made
        // the contract depend on argv ORDER: `--gate-json G --frobnicate` wrote a refusal into G, while
        // `--frobnicate --gate-json G` exited on the unknown flag first and left the PREVIOUS run's green
        // document sitting at G. The operator's intent is identical in both spellings.
        // FROM INDEX 0, and BEFORE the unknown-flag rejection below. java's grammar puts the target in
        // `args[0]`, so `rejectUnknownFlag(args[0], …)` fired on the ordinary spelling
        // `--gate-json G <target> --policy P` and exited 2 with the PREVIOUS run's green still at G,
        // while rust/ts/swift wrote a refusal. Flags-before-positional is not an exotic spelling, and
        // §3.3 names an unknown flag as an exit-2 cause that must leave a refusal.
        String preGate = null, prePolicy = null, preTarget = null;
        // ⟨0.28⟩ Was `--json` requested in STDOUT form (bare, or followed by a flag)? And was any
        // `--gate-json -` in the argv (which would also claim stdout)? Learned in this same pre-pass so
        // `armReportStream` can fire below, BEFORE every downstream exit-2 — including an unknown flag.
        boolean preWantJsonStream = false, preAnyGateJsonStream = false;
        // ⟨0.28⟩ Was `--json <file>` requested? The file sink is the analog of `--gate-json <file>` for
        // the report, and takes the same arming + input-exemption treatment one hop upstream: a scan
        // that exits 2 must not leave the PREVIOUS run's report byte-identical on disk, and a `--json`
        // path naming an INPUT of this run must be refused with nothing written.
        String preJsonFile = null;
        // ⟨0.28⟩ every `--json` sink spelling in argv, in order — `-` for the stream form. A run publishes
        // ONE report to ONE sink; see the repeated-sink refusal below the loop.
        var preJsonSinks = new java.util.ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            boolean hasVal = i + 1 < args.length;
            if (args[i].equals("--gate-json") && hasVal && (args[i + 1].equals("-") || !args[i + 1].startsWith("-"))) {
                if (args[i + 1].equals("-")) preAnyGateJsonStream = true;
                preGate = args[++i];
            }
            // ⟨0.28⟩ `--policy` CONSUMES THE NEXT TOKEN ONLY WHEN IT IS VALUE-SHAPED (`-`, or not
            // dash-prefixed) — the SPEC §3.2 "given no value" ruling — and the parse loop below agrees
            // token-for-token. A flag-shaped token is NOT a value: the loop refuses the run there
            // (exit 2, a usage error), and this pre-pass leaves the token LIVE so a sink named after
            // the broken flag is still registered and armed. Both halves of that agreement have been
            // measured as defects. Consuming HERE what the loop refused armed a sink the parse never
            // accepted (`--policy --json X` armed X as a permanent placeholder, SPEC §3.3.1 (1)'s
            // "parsed and accepted" precondition false). Consuming in BOTH places was the fail-open
            // half that alignment then exposed: `--policy --gate-json -` read the operator's verdict
            // sink as a policy FILENAME, measured as exit 2 with NOTHING on the stream where the
            // refusal document belongs (conformance §3.1 (b13)).
            else if (args[i].equals("--policy") && hasVal
                    && (args[i + 1].equals("-") || !args[i + 1].startsWith("-")))
                prePolicy = args[++i];
            else if (args[i].equals("--json") && hasVal && !args[i + 1].startsWith("-")) {
                preJsonFile = args[++i];                                                        // --json <file>
                preJsonSinks.add(preJsonFile);
            } else if (args[i].equals("--json")) {
                preWantJsonStream = true;                                                       // bare / --json <-flag>
                preJsonSinks.add("-");
            }
            else if (!args[i].startsWith("-") && preTarget == null) preTarget = args[i];
        }
        // ⟨0.28⟩ Arm the report-stream shutdown hook so `--json` never leaves stdout empty on an exit-2
        // (unknown flag, unreadable input, misconfiguration, crash). Not armed when `--gate-json -` is
        // also present: that stream is already claimed by the verdict (or by the two-stream refusal doc
        // just below), and a second write from this hook would put two JSON documents on one pipe.
        if (preWantJsonStream && !preAnyGateJsonStream) armReportStream();
        // ⟨0.28⟩ FILE FORM: refuse a `--json <file>` that names an input of this run FIRST (writing
        // nothing would-be-destroyed), then arm the file with the fail-closed report so every downstream
        // exit-2 leaves that document in place rather than the previous run's green. Mirror of the
        // `refuseGateJsonOverAnyInput` + `armGateJson` sequence used for the verdict sink at line ~715.
        // Arming also removes that report's §2.2 sidecars (see armReportJson), which is why the target
        // and policy travel with it — the input exemption covers the sidecars as well.
        // ⟨0.28⟩ A REPEATED `--json` IS REFUSED, the same rule as the repeated `--gate-json` below and for
        // the same reason — two spellings of one rule is the habit this rung has paid for six times.
        // MEASURED on this engine before the change: `--json one.json --json two.json` wrote the report to
        // the LAST path and left the first holding a previous run's document at exit 0 — the ⟨0.27⟩ stale
        // green, arriving through the report sink because the refusal was written for the verdict sink and
        // never extended. Two spellings of one artifact are ONE sink (sameArtifact); the file-and-stream
        // mix is two. Every non-input FILE sink gets the fail-closed ARMED report (the §3.3.1 (2) shape —
        // a report sink's refusal document IS the manifest-carrying empty); the stream form is covered by
        // the armReportStream hook armed above, so stdout carries the same fail-closed document on exit.
        {
            var namedJson = new java.util.ArrayList<String>();
            for (String v : preJsonSinks) {
                boolean seen = false;
                for (String k : namedJson)
                    if (k.equals(v) || (!k.equals("-") && !v.equals("-") && sameArtifact(k, v))) seen = true;
                if (!seen) namedJson.add(v);
            }
            if (namedJson.size() > 1) {
                String tgt = preTarget != null ? preTarget : ".";
                var offending = new java.util.LinkedHashSet<String>();
                for (String sNamed : namedJson)
                    if (!sNamed.equals("-") && gateJsonIsInput(sNamed, tgt, prePolicy)) offending.add(sNamed);
                for (String sNamed : offending)
                    System.err.println("candor: --json " + sNamed + " names an INPUT of this run — "
                            + "refusing (exit 2), and nothing was written there.");
                System.err.println("candor: --json given more than once ("
                        + String.join(", ", namedJson) + ") — refusing (exit 2). A scan publishes ONE "
                        + "report. Naming two sinks says where it goes twice, and the reader of the path "
                        + "that loses cannot tell it lost. Name one, or run the scan twice.");
                for (String sNamed : namedJson) {
                    if (sNamed.equals("-") || offending.contains(sNamed)) continue;
                    armReportJson(sNamed, tgt, prePolicy);   // the fail-closed report, sidecars removed
                }
                System.exit(2);
            }
        }
        if (preJsonFile != null) {
            refuseJsonOverAnyInput(preJsonFile, preTarget != null ? preTarget : ".", prePolicy);
            armReportJson(preJsonFile, preTarget != null ? preTarget : ".", prePolicy);
        }
        if (preGate != null) {
            // ⟨0.28⟩ `--json` BESIDE `--gate-json -`: a report and a verdict cannot share one stream.
            // Decided in the pre-pass so the refusal is stdout's ONLY content — refusing after the report
            // has gone out is the defect rather than the fix. BARE `--json` only: `--json <file>` writes
            // the report somewhere else, which is two artifacts in two places and exactly what was asked.
            if (preGate.equals("-")) {
                boolean bareJson = false;
                for (int i = 0; i < args.length; i++) {
                    if (!args[i].equals("--json")) continue;
                    if (i + 1 >= args.length || args[i + 1].startsWith("-")) bareJson = true;
                }
                if (bareJson) {
                    System.err.println("candor: --json and --gate-json - both name STDOUT — refusing "
                            + "(exit 2). `--json` writes the REPORT there and `--gate-json -` the VERDICT, "
                            + "so this would put two JSON documents on one stream and a consumer parsing "
                            + "it gets neither. Send one to a file, or run the scan twice.");
                    var d = new java.util.LinkedHashMap<String, Object>();
                    d.put("spec", SPEC_VERSION);
                    d.put("ok", false);
                    d.put("refused", true);
                    d.put("reason", "--json and --gate-json - both name stdout — a report and a verdict "
                            + "cannot share one stream");
                    System.out.println(io.poly.candor.model.ReportJson.pretty(d));
                    System.exit(2);
                }
            }
            // ⟨0.28⟩ The DUPLICATE case is decided first: this single-sink guard acts on `preGate` alone
            // — the LAST sink — so `--gate-json - --gate-json <the policy>` exited on the policy before
            // the STREAM was told anything (measured: exit 2, stdout zero bytes).
            // ⟨0.28⟩ A REPEATED --gate-json IS REFUSED, AND EVERY PATH NAMED GETS THE REFUSAL. The loop
            // above keeps the LAST, which is what the parse honours — and that is exactly the behaviour
            // this rung refuses: measured, this engine wrote the verdict to the last path and left the
            // first holding a previous run's {"ok": true} while the gate FIRED. The ⟨0.27⟩ stale green,
            // reached by a spelling nobody had considered, and worse than the case arming was built for
            // because the run did not fail and the operator's own command named the path that lies.
            //
            // After the input-collision guard, before arming: a sink that is an INPUT is refused having
            // written nothing, and that exemption outranks this one.
            var namedSinks = new java.util.ArrayList<String>();
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("--gate-json") && i + 1 < args.length
                        && (args[i + 1].equals("-") || !args[i + 1].startsWith("-"))) {
                    String v = args[++i];
                    // Two spellings of one path are ONE sink (the §3.3.1 artifact rule), not a duplicate.
                    boolean seen = false;
                    for (String k : namedSinks)
                        if (k.equals(v) || (!k.equals("-") && !v.equals("-") && sameArtifact(k, v))) seen = true;
                    if (!seen) namedSinks.add(v);
                }
            }
            if (namedSinks.size() > 1) {
                String list = String.join(", ", namedSinks);
                // ⟨0.28⟩ THE INPUT EXEMPTION COVERS THE PATH, NOT THE RUN. `refuseGateJsonOverAnyInput`
                // exits having written nothing — right for the offending path, but it used to take the
                // run with it, leaving the OTHER named sink publishing whatever it held. Ask without
                // exiting, then write to every path that is not an input.
                var offending = new java.util.LinkedHashSet<String>();
                for (String sNamed : namedSinks)
                    if (gateJsonIsInput(sNamed, preTarget != null ? preTarget : ".", prePolicy)) offending.add(sNamed);
                if (offending.size() == namedSinks.size()) {
                    // Every named sink is an input: refuse, having written nothing anywhere.
                    refuseGateJsonOverAnyInput(namedSinks.get(0), preTarget != null ? preTarget : ".", prePolicy);
                    System.exit(2);
                }
                for (String sNamed : offending)
                    System.err.println("candor: --gate-json " + sNamed + " names an INPUT of this run — "
                            + "refusing (exit 2), and nothing was written there.");
                System.err.println("candor: --gate-json given more than once (" + list + ") — refusing "
                        + "(exit 2). A gate publishes ONE verdict. Naming two sinks says where it goes "
                        + "twice, and the reader of the path that loses cannot tell it lost. Name one, "
                        + "or run the gate twice.");
                var doc = new java.util.LinkedHashMap<String, Object>();
                doc.put("spec", SPEC_VERSION);
                doc.put("ok", false);
                doc.put("refused", true);
                doc.put("reason", "--gate-json was given more than once (" + list + ") — a run publishes "
                        + "one verdict to one sink");
                String text = io.poly.candor.model.ReportJson.pretty(doc);
                for (String sNamed : namedSinks) {
                    if (offending.contains(sNamed)) continue;      // exemption scoped to this path
                    if (sNamed.equals("-")) { System.out.println(text); continue; }
                    try {
                        Files.writeString(Path.of(sNamed), text + "\n");
                    } catch (IOException | RuntimeException e) {
                        System.err.println("candor: could not write the refusal to --gate-json " + sNamed
                                + " (" + e.getMessage() + ")");
                    }
                }
                System.exit(2);
            }
            // Exactly one sink: the ordinary guard, which exits having written nothing.
            refuseGateJsonOverAnyInput(preGate, preTarget != null ? preTarget : ".", prePolicy);
            armGateJson(preGate);
            // ⟨0.27⟩ the stream sink's analog of arming — a hook, because a stream cannot hold a
            // placeholder. See armGateJsonStream.
            if (preGate.equals("-")) armGateJsonStream();
        }
        // THE TARGET NEED NOT COME FIRST. It used to have to — `rejectUnknownFlag(args[0], emptySet, …)`
        // rejected any leading flag — so `candor --gate-json G <target> --policy P` failed as an "unknown
        // flag" while rust, ts and swift all scanned it. One contract, four grammars is the thing this
        // family exists not to be, and the spelling is an ordinary one.
        if (preTarget == null) {
            System.err.println("candor: no scan target (usage: candor <dir-or-jar> [--json <file>] "
                    + "[--policy <file>] [--gate-json <file>])");
            System.exit(2);
        }
        boolean tookTarget = false;              // the single positional, wherever in argv it sits
        for (int i = 0; i < args.length; i++) {
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
                gateZeroMatch.clear();
                // (armed already by the pre-pass above — SPEC §3.3.1 ⟨0.27⟩ "arm at the instant the
                // sink is known"; arming here made the contract depend on argv order.)
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
                // SPEC §3.2 ⟨0.28⟩: a flag-shaped next token means --policy was GIVEN NO VALUE — the
                // §6.2 unknown-flag rule one position over. Consuming it as a filename made that cause
                // unreachable (no argv could produce it) and swallowed the sink the token named:
                // `--policy --gate-json -` exited 2 with NOTHING on the stream where the refusal
                // document belongs (conformance §3.1 (b13)). The pre-pass left the token live, so the
                // sink it names is already armed and this exit leaves the refusal there. A bare `-`
                // stays a value (it fails a moment later as an unreadable policy file, loudly).
                if (args[i + 1].startsWith("-") && !args[i + 1].equals("-")) {
                    System.err.println("candor: --policy was given no value — the next token " + args[i + 1]
                            + " is a flag, not a file (a file really named that is spelled ./" + args[i + 1] + ")");
                    System.exit(2);
                }
                policyArg = args[++i];
            } else if (!args[i].startsWith("-") && !tookTarget) {
                tookTarget = true;                       // the single positional, wherever it sits
            } else {
                rejectUnknownFlag(args[i], scanFlags, "candor <dir-or-jar> [--json <file>] [--policy <file>] [--gate-json <file>]");
                // A BARE unexpected token is the same failure class as an unknown flag: candor's scan
                // grammar has exactly ONE positional (the target), so a SECOND bare token here is a
                // displaced value (a flag above swallowed its neighbour) or a typo — silently dropping
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
        Path scanTarget = Path.of(preTarget);
        // Load `.candor/config` for this run, ANCHORED TO THE SCAN TARGET (walk up from target/classes to
        // the repo root's .candor/config) — never to the process CWD, which would make the "config travels
        // with the code" promise depend on where the command was launched from. The layer sits UNDER the
        // env vars (which sit under the CLI flags); configured-but-unreadable fails loud (exit 2).
        config = Config.forTarget(scanTarget);
        enforceEnginePin(config);
        if (!Files.exists(scanTarget)) {
            System.err.println("candor: no such path: " + args[0]);
            System.err.println("        point candor at COMPILED classes (target/classes · build/classes/java/main) or a built .jar.");
            System.err.println("        no build yet? run `mvn -q compile` or `./gradlew classes` first.");
            refuseGateJson("no such path: " + args[0] + " — point candor-java at compiled classes "
                    + "(target/classes, build/classes/java/main) or a built .jar.");
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
        //
        // ⟨0.24⟩ …but read from the POLICY's config, not the TARGET's, when --policy was given explicitly
        // (SPEC §3.1). MEASURED at 2cdc443 with `unknown-alias corp = native` beside the policy and none
        // beside the target: `scan --policy P` exited 1 (alias unresolved → `deny Unknown[corp]` widened
        // to bare `deny Unknown`) where `gate --report R --policy P` exited 0 (alias resolved → no match).
        // Same report, same policy, two verdicts — §3.1's byte-equality MUST broken by a file that is
        // neither. Vocabulary travels with the policy that uses it; `net-partner` and `deps` stay
        // TARGET-anchored below, because they describe the thing being scanned.
        //
        // ⟨0.24⟩ …AND THE ANCHOR IS THE RESOLVED POLICY PATH, HOWEVER IT WAS SUPPLIED. This first keyed on
        // `policyArg != null`, i.e. on the policy having arrived as a FLAG — so a policy supplied through
        // `CANDOR_POLICY` (CI's primary channel) or the config `policy` key fell back to the TARGET's
        // config and expanded its aliases there. MEASURED, one policy and one target, three channels:
        //   --policy <file>              exit 1, resolved at the policy's config
        //   gate --report … --policy     exit 1, resolved at the policy's config
        //   CANDOR_POLICY=<file>         exit 0, ok:true, resolved at the TARGET's config  ← a silent PASS
        // The ruling is about where policy VOCABULARY lives, and a policy does not change what it is
        // according to how the operator handed it over; keying on the flag made the fail-open case the one
        // CI actually uses. The resolution ladder itself (flag → env → config `policy`) is unchanged and is
        // read HERE so the anchor and the gate below can never disagree about which file is the policy.
        String policyPath = policyArg != null ? policyArg : config.value("policy", Mode.POLICY.envVar());
        Config vocab = policyVocabularyFor(policyPath, config);
        ctx().unknownAliases.putAll(vocab.unknownAliases());
        if (!vocab.unknownAliases().isEmpty() && vocab.source() != null)
            ctx().vocabularySource = vocab.source().toString();
        ctx().netPartners.addAll(config.netPartners());
        if (!config.netPartners().isEmpty() && config.source() != null)
            ctx().netPartnersSource = config.source().toString();   // ⟨0.31⟩ same object, so same file // ⟨0.20⟩ Net destination-class known-partner hosts

        // Fail loud on an EMPTY scan: a path that exists but holds no .class files (a source dir, an
        // unbuilt module, or a failed build) would otherwise report "0 functions reach effects" — which
        // reads as a clean, pure project rather than "nothing was analyzed", and would let a gate pass
        // trivially on a build that never produced bytecode. candor reads bytecode, not source.
        if (ctx().ALL.isEmpty()) {
            System.err.println("candor: no .class files found under " + args[0] + " — nothing to analyze.");
            System.err.println("        candor reads BYTECODE, not source — point it at COMPILED output");
            System.err.println("        (target/classes · build/classes/java/main) or a built .jar.");
            System.err.println("        no build yet? run `mvn -q compile` or `./gradlew classes` first.");
            refuseGateJson("no .class files found under " + args[0] + " — candor-java reads BYTECODE, not "
                    + "source; point it at compiled output (target/classes, build/classes/java/main) or a "
                    + "built .jar. Exit 2 (unevaluable): a target this engine cannot read is not a clean scan.");
            System.exit(2);
        }

        // ⟨0.29⟩ THE NUDGE, and it is this engine's whole answer for its own exclusion kind. The other
        // three arms exclude by a SCOPE decision — a build script, a tsconfig program, a SwiftPM target —
        // and the peek reads what they skipped. candor-java reads BYTECODE, so a `.java` with no compiled
        // class is not a scope decision and cannot be peeked at all; it is closer to an operator error,
        // and the honest response is to say plainly how much of the tree the verdict is NOT about. The
        // report carries the same fact as an `excluded` class with `peeked: false`, so an empty
        // `outOfScope` cannot be misread as "and I checked those too".
        long uncompiled = ctx().excluded.values().stream().filter("source-without-class"::equals).count();
        if (uncompiled > 0) {
            System.err.println("candor-java: " + uncompiled + " JVM source file(s) under " + args[0]
                    + " have no compiled class — candor reads BYTECODE, so nothing in them was judged.");
            System.err.println("             " + ctx().ALL.size() + " class(es) were. If that ratio is a surprise,"
                    + " this scan is answering about a fraction of the project:");
            System.err.println("             build it and scan target/classes · build/classes/java/main, or a built .jar.");
        }
        // ⟨0.29⟩ THE PEEK, before the report is serialised — see peekExcluded. Placed HERE and not in the
        // gate block below because the gate runs AFTER the report is written: computing it there would put
        // the finding on stderr and leave it out of the artifact, which is the split ⟨0.26⟩ calls worse
        // than saying nothing.
        peekExcluded(policyPath);
        phase("peek");

        // JSON output is orthogonal — write first so `--json` can snapshot a baseline. The report needs
        // the all-classes ClassConformance; compute it once here so the gate below can reuse it rather
        // than recompute (the §5 two-pass walk) on a --json + CANDOR_STRICT run.
        ClassConformance ccFull = (jsonOut != null) ? classConformance(inferred) : null;
        phase("class-conformance");
        if (jsonOut != null) {
            try {
                writeReport(inferred, jsonOut, ccFull);
                phase("report-write");
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
        // ⟨0.24⟩ the SAME resolved path the vocabulary anchored on above — one resolution, so the anchor and
        // the gate cannot disagree about which file is the policy (`--policy` still takes precedence).
        String policy = policyPath;
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
        if (baseline != null) violations += checkBaseline(inferred, baseline,
                config.fromFile("baseline", Mode.BASELINE.envVar()));
        // ⟨0.24⟩ PRECEDENCE BINDS THE VERDICT, NOT THE POLICY GATE (SPEC §3.1). The three producers above
        // record into THIS verdict and run BEFORE the policy by design, so a policy the engine cannot
        // honour must not delete what they already established: the refusal is REPORTED back here
        // (Policy.checkPolicyOutcome) and weighed, never taken inside the policy gate. The arm below is
        // keyed on "this run evaluated nothing" (violations == 0) — never on "this run ended refused",
        // which is exactly the conflation §3.1 forbids.
        //
        // The --gate-json sink travels into the sole-refusal arm so an unreadable policy refuses WITH a
        // document instead of exiting 2 over a path CI will re-read yesterday's verdict from.
        String policyRefusal = null;                                  // set only when a violation dominates it
        java.util.List<String[]> unevaluated = new ArrayList<>();     // ⟨0.24⟩ {rule, why}, one row per rule
        if (policy != null) {
            phase("gate-pre");
            Policy.PolicyOutcome po = Policy.checkPolicyOutcome(inferred, policy);
            phase("gate-policy");
            violations += po.violations();
            if (po.refusal() != null) {
                System.err.println("candor-java: " + po.refusal());
                if (violations == 0) {   // the refusal is the SOLE outcome — nothing certain stands above it
                    writeRefusedGateJson(gateJson, po.refusal(), po.unevaluated());
                    System.exit(2);
                }
                policyRefusal = po.refusal();
                unevaluated.addAll(po.unevaluated());
            }
        }
        // AS-EFF-007 is a heuristic ADVISORY (spec §6): emit findings but never fail CI on its own.
        int advisories = ctx().taintEnabled ? checkTaint(inferred) : 0;
        // THE GREEN LINE IS PRINTED BELOW, AFTER THE EXIT-2 ARMS — not here. Measured 2026-08-19: this
        // printed `candor-java: no violations` and the run then exited 2, NOT certified, because a file
        // outside the scan performs a denied effect (⟨0.30⟩) or a class could not be analyzed (⟨0.21⟩).
        // Exit code and verdict document were correct; the human channel said pass. rust and ts reach
        // their green line only after both arms have returned, so this was a four-way divergence too.
        phase("gate-evaluate");
        boolean gateGreen = violations == 0 && advisories == 0;
        // FAILURE-only pointer at the engine's own remedy verb: appended AFTER the AS-EFF lines, on the
        // SAME stream (`gate`), so a clean run stays byte-identical and the pinned violation-line shapes,
        // exit codes and --gate-json verdict are untouched (append-only, human channel only).
        if (violations > 0) gate.println("→ candor fix-gate names the remedy for each");
        // …and the MIRROR of the fix above: exit 1 must not read as "the policy ran and this is all it
        // found". Say on the human channel what the document says under `unevaluated` (⟨0.27⟩ — the
        // composed document is a VERDICT and carries no `refused`/`reason`; see writeGateJson).
        if (policyRefusal != null)
            gate.println("candor-java: exiting 1 on the violation(s) above — they were established BEFORE "
                    + "the policy was read and their evidence does not depend on it, so the refusal cannot "
                    + "un-reject the run (SPEC §3.1). The policy itself was NOT evaluated: "
                    + unevaluated.size() + " rule(s) went unevaluated, named in the verdict document.");
        // machine verdict (before exit) — clean run writes ok:true,[]
        writeGateJson(gateJson, violations, scanGateFacts(), unevaluated, policyRefusal);
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
        // ⟨0.30⟩ THE SCOPE HALF OF THE SAME POSTURE, and the same exit. EXIT 2, NOT 1: these functions are
        // not in `violations` and not in `functions`, because the gate did not judge them — exit 1 would
        // claim "I judged your code and it breaks the policy", which is false in the other direction. The
        // violation exit above still dominates: certain beats unevaluable.
        var oosFindings = ctx().outOfScope;
        if (gateConfigured && oosFindings != null && !oosFindings.isEmpty()) {
            System.err.println("candor-java: gate NOT certified — " + oosFindings.size()
                    + " function(s) OUTSIDE this scan's scope perform an effect this policy denies (named "
                    + "above); the gate did not judge them, so the verdict is incomplete rather than a pass");
            System.exit(2);
        }
        // ⟨0.32⟩ THE THIRD CAUSE — CODE THIS RUN ADMITS IT NEVER READ. See the verdict writer for the
        // measurement: `deny Exec` answered ✓ at exit 0 over a tree holding an UNCOMPILED `Deploy.java`
        // calling `Runtime.exec("curl … | sh")`, because this engine reads bytecode and the peek cannot
        // open a source file. The ⟨0.30⟩ arm above keys on what the peek FOUND, and a peek that could
        // not open the file finds nothing — indistinguishable from finding it clean.
        //
        // AFTER the ⟨0.30⟩ arm and after the violation exit, deliberately: certain beats unevaluable, and
        // a CONCRETE denied effect outside the scan is a better message than "something went unread".
        // NOT over a REFUSED policy. A refusal is not a verdict — §3.1 binds "any report a scan
        // produced", and a run that could not read its policy has no verdict for incompleteness to
        // qualify. Saying "NOT certified because files went unread" over a run that never evaluated
        // anything would replace the operator's actual problem (their policy did not parse) with a
        // downstream one. The refusal already owns the exit.
        if (gateConfigured && policyRefusal == null) {
            java.util.List<String> unread = new ArrayList<>();
            for (var c : excludedClasses())
                if (!c.peeked() && !c.judgedElsewhere()) unread.add(c.cls() + " (" + c.count() + ")");
            if (!unread.isEmpty()) {
                System.err.println("candor-java: gate NOT certified — this scan did not READ "
                        + String.join(", ", unread) + ". Their effects are absent because nothing looked, "
                        + "not because there are none, so the verdict is INCOMPLETE rather than a pass. "
                        + "Build the sources and scan the compiled output, or narrow the policy's scope.");
                System.exit(2);
            }
        }
        // …and only NOW is the gate green: every exit-2 arm above has been passed, so `no violations` is
        // a claim this run can support. See the note at its old position for what printing it earlier said.
        if (gateGreen) gate.println("candor-java: no violations");
    }

    /** ⟨0.15 staged⟩ The κ-coverage ledger, computed the ONE shared way for its three consumers — the
     *  per-scan stderr disclosure, the report envelope's `coverage` field (ReportWriter), and the
     *  --gate-json advisory — so the three can never disagree on names or counts. An external package the
     *  bytecode demonstrably calls where the classifier never fired AND no chained dep report covers it:
     *  its effects are INVISIBLE to the scan (absent, NOT a claim of purity). Sorted by call count
     *  descending, then name (the stderr line's order, kept for the wire too).
     *
     *  Coverage is a REVIEW claim, not a resolution outcome. This filter deliberately does NOT consult
     *  `kappaClassified` (packages where κ fired at least once). That set is an unvouched proxy: κ matching
     *  `FileUtils.readFileToString` says nothing about whether `FilenameUtils.getName` is modeled, so one
     *  classified call was clearing the blind marker for every OTHER call shape into the same package. The
     *  vouching mechanism is the curated prefix list (`kappaCovers`) plus a chained dep report — both of
     *  which someone reviewed. `blindDirect` already records the per-call-site datum and `literalFixpoint`
     *  already propagates it, so the per-method truth was present all along and only this filter hid it. */
    static List<Map.Entry<String, Integer>> kappaUncovered() {
        // Packages reached ONLY by a non-call site carry a count of 0 — truthful (no call went there) and
        // it keeps the list a superset of every package a function's `invisible` can name.
        Map<String, Integer> all = new TreeMap<>(ctx().kappaSeen);
        for (String p : ctx().kappaBlindPkgs) all.putIfAbsent(p, 0);
        return all.entrySet().stream()
                .filter(e -> !ctx().depCoveredPkgs.contains(e.getKey()))
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .collect(Collectors.toList());
    }

    /** `--gate-json`: write the structured gate verdict `{ spec, ok, violations:[{rule,fn,effects,detail}] }` — the
     *  machine analog of the AS-EFF console lines, from the SAME diagnostics (captured in {@link #diag}), so
     *  it can never disagree with the exit code. `ok` is the CI verdict (advisory AS-EFF-007 lines appear in
     *  the list but do NOT clear `ok`). Consumed by the PR-native SARIF reporter (integrations/github). */
    static void writeGateJson(String path, int violations) {
        writeGateJson(path, violations, scanGateFacts());
    }

    /** ⟨0.24⟩ The non-violation facts a gate verdict carries, sourced independently of HOW the gate was
     *  reached: a scan reads them from its own live state ({@link #scanGateFacts}), {@code gate --report}
     *  reads the same three from the §2 report ENVELOPE it was handed ({@code analyzed.count},
     *  {@code unanalyzed}, {@code coverage.uncovered} — the wire fields these were written from). Splitting
     *  them out is what lets ONE verdict writer serve both routes, so the two documents cannot drift in
     *  shape and a consumer cannot tell a scanned verdict from a report-gated one. */
    record GateFacts(int analyzedCount, java.util.List<String[]> unanalyzed,
                     java.util.List<Map.Entry<String, Integer>> uncovered,
                     java.util.List<io.poly.candor.model.Report.OutOfScope> outOfScope,
                     /** ⟨0.32⟩ exclusion classes this run did NOT read — `excluded[].peeked == false`. */
                     java.util.List<String> unpeeked) {}

    static GateFacts scanGateFacts() {
        java.util.List<String[]> un = new ArrayList<>();
        for (var e : ctx().unanalyzed.entrySet()) un.add(new String[]{e.getKey(), e.getValue()});
        // ⟨0.30⟩ the peek's findings travel with the other three, for the reason the doc above gives: ONE
        // verdict writer serves both routes, so the two documents cannot drift. A scan reads them from
        // live state; `gate --report` reads them from the report envelope it was handed.
        var oos = ctx().outOfScope == null
                ? java.util.List.<io.poly.candor.model.Report.OutOfScope>of()
                : java.util.List.copyOf(ctx().outOfScope);
        // ⟨0.32⟩ the exclusion classes this run did not READ. Derived from the same builder the report
        // publishes, so the verdict and the document cannot disagree about which classes were opened.
        java.util.List<String> unpeeked = new ArrayList<>();
        for (var c : excludedClasses())
            if (!c.peeked() && !c.judgedElsewhere()) unpeeked.add(c.cls());
        return new GateFacts(ctx().edges.keySet().size(), un, kappaUncovered(), oos, unpeeked);
    }

    static void writeGateJson(String path, int violations, GateFacts facts) {
        writeGateJson(path, violations, facts, java.util.List.of());
    }

    /** ⟨0.24⟩ As above, plus the rules the run could NOT evaluate (SPEC §3.1's corrected precedence: a
     *  certain violation dominates a refusal, and "the refusal message MUST still disclose which rules
     *  could not be evaluated"). Each row is {@code {rule, why}}. Empty on every path but
     *  {@code gate --report}'s answerability refusals, so a scan's verdict is byte-identical to before —
     *  and so is a gate verdict over a report this engine wrote, which is what §3.1's byte-equality MUST
     *  binds. */
    static void writeGateJson(String path, int violations, GateFacts facts,
                              java.util.List<String[]> unevaluated) {
        writeGateJson(path, violations, facts, unevaluated, null);
    }

    /**
     * ⟨0.27⟩ As above, on the run whose verdict a violation decides while a policy refusal stands beside
     * it (SPEC §3.1: <b>precedence binds the VERDICT, not the policy gate</b>).
     *
     * <p><b>The {@code refused}/{@code reason} keys this overload used to emit are GONE, and that is the
     * ⟨0.27⟩ composed-document ruling, not a cleanup.</b> This engine put {@code refused: true} beside
     * {@code violations} — and the four engines wrote four spellings of this one document. But
     * {@code refused} is the refusal document's DISCRIMINATOR, and its pinned meaning is <i>"the gate is
     * making no claim about violations"</i> — precisely the claim a violations-bearing document IS
     * making. A consumer keying on {@code refused} (which the refusal-document clause invites) filed a
     * certain violation under "no claim". The earlier javadoc here argued dropping the refusal half
     * "publishes an exit 1 that reads as a policy that ran clean" — right about the harm, wrong about the
     * channel: the disclosure is {@code unevaluated}, one entry PER RULE of the refused policy
     * ({@link Policy#unhonouredRules}), so no rule silently reads as evaluated-and-passed and no key
     * carries two contradictory meanings. {@code refusal} is still taken as a parameter only to keep the
     * call site honest about which case it is in; it decides nothing but the stderr sentence there.
     */
    static void writeGateJson(String path, int violations, GateFacts facts,
                              java.util.List<String[]> unevaluated, String refusal) {
        if (path == null) return;
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("spec", SPEC_VERSION);
        // ⟨0.21⟩ COMPLETENESS MANIFEST (Gap 2): a gate over code candor could NOT fully analyze (skipped
        // unparseable classes) must NOT read green — their effects are invisible, so a `deny`/`pure` that
        // "passes" over them is a false-pure. `ok` requires BOTH no violation AND a complete analysis.
        // ⟨0.30⟩ THE SECOND CAUSE. `unanalyzed` is "I opened this class and could not read it";
        // `outOfScope` is "I never opened it, and when the peek looked afterwards it performed the effect
        // this policy denies". Both mean the gate could not see enough of the tree to certify it, so both
        // suppress `ok`. Reverses ⟨0.29⟩'s "the verdict does not move" on the measurement that the peek
        // resolves a CONCRETE denied effect rather than uncertainty.
        var oos = facts.outOfScope();
        boolean scopeIncomplete = oos != null && !oos.isEmpty();
        // ⟨0.32⟩ THE THIRD CAUSE — CODE THE ENGINE ADMITS IT NEVER READ.
        //
        // ⟨0.30⟩ suppressed `ok` when the PEEK FOUND a denied effect outside the judged set. That keys the
        // verdict on what the peek found, and a peek that could not open a file finds nothing — which is
        // byte-identical to finding it clean. MEASURED: `deny Exec` answered ✓ at exit 0 over a tree
        // holding `Deploy.java` calling `Runtime.exec("curl … | sh")`, uncompiled, because candor-java
        // reads BYTECODE and the peek cannot open a source file. `excluded` said `peeked: false` — this
        // engine stating plainly that it did not read those files — and that flag moved nothing.
        //
        // It is the THREE-ROW RULE at file-set scale: absence under a key licenses a claim only if the key
        // COULD have had a body. `peeked: false` is exactly the case where it could not, so the verdict is
        // INCOMPLETE rather than a pass — the same reading ⟨0.30⟩ gave `outOfScope`, and the same one
        // candor-swift already gave `unanalyzed` ("a gate cannot be green over unanalyzed code").
        //
        // Both routes reach it identically: `excluded` rides the REPORT, so `gate --report` re-derives
        // this from the document rather than needing a target — which is what the `net-partner` attempt
        // could not do, and why that one broke §3.1 route equality and this one does not.
        boolean unread = facts.unpeeked() != null && !facts.unpeeked().isEmpty();
        boolean incomplete = !facts.unanalyzed().isEmpty() || scopeIncomplete || unread;
        out.put("ok", violations == 0 && !incomplete);
        // ⟨0.21⟩ (Gap 1) the analyzed-universe count, so a --gate-json consumer sees the scan's scope from the
        // verdict alone (mirrors the report envelope's `analyzed`).
        var an = new java.util.LinkedHashMap<String, Object>();
        an.put("count", facts.analyzedCount());
        out.put("analyzed", an);
        policyVocabularyJson(out);
        netPartnersJson(out);
        out.put("violations", gateViolations);
        // ⟨0.24⟩ THE RULES THIS RUN COULD NOT EVALUATE. A verdict that exits 1 over a policy one of whose
        // rules was refused is CERTAIN about the violation and silent about the rest — so the rest is said
        // here, in the same document, rather than only on a stderr line a CI wrapper discards. Omitted when
        // empty, so every other route's verdict is byte-identical to a pre-⟨0.24⟩ one.
        if (!unevaluated.isEmpty()) out.put("unevaluated", unevaluatedJson(unevaluated));
        // ⟨0.27⟩ SPEC §4 `zeroMatch` — the rules whose scope bound NO function, verbatim: the same list
        // the stderr lines carry, in the machine channel. Code-point sorted + deduplicated (the
        // `viaDispatchOn` collation — Query.BY_CODE_POINT, because String.compareTo is UTF-16 order and
        // the raw line is built from user identifiers). Omitted when empty; never consulted for `ok`.
        if (!gateZeroMatch.isEmpty()) {
            var zm = new java.util.TreeSet<String>(Query.BY_CODE_POINT);
            zm.addAll(gateZeroMatch);
            out.put("zeroMatch", new ArrayList<>(zm));
        }
        // ⟨0.28⟩ SPEC §6.2 `ignored` — the policy lines the parse DROPPED, {line, text, reason} verbatim:
        // the same lines the per-line stderr warnings name, in the machine channel, so a consumer can see
        // that the gate it is reading is smaller than the gate that was written (the 90%-gateless green).
        // Omitted when nothing was dropped, so a clean policy's verdict stays byte-identical. Distinct
        // from `unevaluated` (rules that PARSED and could not be answered); never consulted for `ok`.
        var ignored = Policy.ignoredLinesJson();
        if (!ignored.isEmpty()) out.put("ignored", ignored);
        // ⟨0.21⟩ (Gap 2) the machine-legible incompleteness: the units candor couldn't analyze, so a CI/agent
        // reading the JSON learns WHY the gate can't certify — the stderr warning alone used to hide this from
        // a machine. `incomplete:true` + the list; the caller exits 2 (could-not-fully-evaluate). Tom's call
        // 2026-07-17: emit a structured reason on the incomplete path rather than nothing (refines §3.3.1 to
        // "no ok:true GUESS" — ok:false + incomplete:true is honest, never a fabricated pass).
        if (incomplete) {
            out.put("incomplete", true);
            if (!facts.unanalyzed().isEmpty()) {
                List<Map<String, Object>> un = new ArrayList<>();
                for (String[] e : facts.unanalyzed()) {
                    var m = new java.util.LinkedHashMap<String, Object>();
                    m.put("path", e[0]);
                    m.put("reason", e[1]);
                    un.add(m);
                }
                out.put("unanalyzed", un);
            }
        }
        // ⟨0.30⟩ …and WHICH functions made it incomplete, in the machine channel — the same entries the
        // report carries, so `gate --report` re-emits them from the report and §3.1's byte-equality holds
        // by construction. Omitted when empty, so a clean verdict stays byte-identical to a ⟨0.29⟩ one.
        if (scopeIncomplete) out.put("outOfScope", io.poly.candor.model.ReportJson.outOfScopeJson(oos));
        // ⟨0.15 staged⟩ the coverage ADVISORY (COVERAGE-DESIGN §3): when the κ ledger is non-empty the
        // verdict discloses it — a gate verdict over partially-covered code must not read as total.
        // VERDICT-PRESERVING (the ⟨0.9⟩ provable-purity auto-disclosure precedent): ok/violations/exit
        // are untouched — a gate does NOT fail on uncovered deps (nearly every real scan has some); the
        // policy author sees the note and decides (`deny Unknown` stays the opt-in strict posture).
        // Omitted when fully covered, so that verdict stays byte-identical to a pre-⟨0.15⟩ one.
        List<Map.Entry<String, Integer>> uncov = facts.uncovered();
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
            gateDocEmitted = true;   // the stream-sink hook must not add a second document
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

    /**
     * ⟨0.24⟩ <b>ARM THE `--gate-json` PATH FAIL-CLOSED THE MOMENT IT IS NAMED — SPEC §3.1's stale-document
     * rule, over its CONDITION rather than over the exit sites it was found at.</b>
     *
     * <p>{@code 1503368} made a refusal write its document; {@code 901f14d} generalised that over machine
     * output PATHS: <i>"on any exit-2, every machine output path the invocation requested is written
     * fail-closed, or is not left holding a previous run's answer."</i> Both were implemented at the exit
     * sites that had been measured. MEASURED here, on a path a clean run had left {@code ok: true}:
     * <pre>
     *   candor classes --policy p --gate-json g      -> exit 0, g = {ok: true, violations: []}
     *   CANDOR_BASELINE=&lt;no-provenance&gt; …--gate-json g -> exit 2, g STILL READS ok: true
     *   candor /nonexistent --policy p --gate-json g -> exit 2, g STILL READS ok: true
     * </pre>
     * Two different causes, one stale green, and a CI wrapper reading that path unconditionally passes.
     *
     * <p>Threading the sink into each of the ~20 {@code System.exit(2)} sites is the fix scoped to the
     * POSITION, and it is wrong twice over: it is the error this rung has now recorded four times, and it
     * still leaves every site nobody enumerated — a crash, an OOM, a CI timeout, a future exit. So the
     * document is written when the flag is PARSED, before anything can fail, saying exactly that. Every
     * normal path overwrites it with the verdict, so a completed run's bytes are unchanged; anything that
     * does not complete leaves a document whose naive read is FAIL.
     *
     * <p>{@code -} (stdout) is excluded: that stream carries exactly ONE document, written at the end, and
     * a placeholder there would put two in a consumer's pipe. A placeholder that cannot be WRITTEN is a
     * warning, not a refusal — the end-of-run write hits the same path and fails loudly and specifically.
     */
    /**
     * SPEC §3.3.1 ⟨0.27⟩ — is {@code a} the SAME ARTIFACT as {@code b}?
     *
     * <p>Not a string comparison. {@code --policy /w/P --gate-json ./P} run from {@code /w} names one
     * file twice, and candor-rust shipped a guard that compared path components and was defeated by
     * exactly that spelling. Where both sides exist this is device+inode via {@link Files#isSameFile},
     * which also catches a symlink and a hard link; where the sink does not exist yet (the normal case —
     * we are about to create it) the parent directory is resolved instead and the file name appended.
     *
     * <p>Fails CLOSED on error in the sense that matters: an exception means "cannot prove they differ"
     * only for exotic paths, and returning false there preserves the previous behaviour rather than
     * refusing a legitimate run. The collision this guards against is a mistake, not an attack.
     */
    static boolean sameArtifact(String a, String b) {
        if (a == null || b == null || a.equals("-") || b.equals("-")) return false;
        try {
            Path pa = Path.of(a), pb = Path.of(b);
            if (Files.exists(pa) && Files.exists(pb)) return Files.isSameFile(pa, pb);
            // ⟨0.28⟩ A DANGLING SYMLINK STILL NAMES ITS TARGET. `Files.exists` FOLLOWS the link, so a link
            // whose target does not exist yet answered false above and fell to the parent-resolved form,
            // which compares the LINK's own path — so `--gate-json dl.json --gate-json target.json` was
            // refused as two sinks when it is one artifact and one verdict. A false refusal of a legal
            // command, and the mirror of the stale green.
            return resolveForCompare(resolveSinkArtifact(pa)).equals(resolveForCompare(resolveSinkArtifact(pb)));
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /**
     * ⟨0.28⟩ SPEC §3.3.1 "AND THE SCAN TARGET EXPANDS TO THE FILES THE RUN WILL PARSE" — is {@code sink}
     * a path UNDER the (directory) scan target bearing an extension this engine parses
     * ({@link Loader#parseableSourceName})?
     *
     * <p>The exact-artifact input rule refuses a sink that IS the target and permits everything else,
     * which left this residual: MEASURED on this engine before the change, {@code candor clsA --json
     * clsA/evil.class} ARMED the placeholder into the class tree, the walk then read the JSON bytes as
     * bytecode ("skipped 1 unparseable class file(s) … Unsupported class file major version 24942" — the
     * major version is the placeholder's own text), and the run finished GREEN with the report sitting at
     * a {@code .class} path. Had a real class of the operator's code lived there, arming would have
     * destroyed it AND the scan silently skipped the wreckage. The full file set is unknowable at arming
     * time (arming precedes the walk, deliberately — §3.3.1 (1)); the engine's own source extensions are
     * not, and that is the whole of the check. NEVER containment in general: {@code <dir>/.candor/
     * report.json} is under the target, is not a source file, and stays permitted — the control that
     * separates this from the containment rule the spec explicitly rejects.
     */
    static boolean sinkParseableUnderTarget(String sink, String target) {
        if (sink == null || sink.equals("-") || target == null) return false;
        try {
            Path t = Path.of(target);
            if (!Files.isDirectory(t)) return false;   // a jar/zip target has no "under"; exact-artifact covers it
            Path resolved = resolveSinkArtifact(Path.of(sink));
            Path name = resolved.getFileName();
            if (name == null || !Loader.parseableSourceName(name.toString())) return false;
            return realishPath(resolved).startsWith(t.toRealPath());
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** Symlink-resolved as far as the filesystem allows, for a path whose TAIL may not exist yet: the
     *  nearest EXISTING ancestor is resolved really, the missing remainder re-appended lexically. The
     *  parent-only {@link #resolveForCompare} is not enough for the under-target check: a sink named in a
     *  not-yet-existing SUBDIRECTORY of the target (`--gate-json <target>/lib/x.jar`) kept its unresolved
     *  spelling while the target resolved really, so on a symlinked temp root (macOS `/var` →
     *  `/private/var`) the containment test silently failed — MEASURED: the test-suite reproduction was
     *  "protected" only by the write failing on the missing directory, the accident-is-not-an-
     *  implementation arm the spec names. */
    private static Path realishPath(Path p) {
        Path abs = p.toAbsolutePath().normalize();
        Path cur = abs, rest = null;
        while (cur != null && !Files.exists(cur)) {
            Path leaf = cur.getFileName();
            if (leaf == null) return abs;
            rest = rest == null ? leaf : leaf.resolve(rest);
            cur = cur.getParent();
        }
        if (cur == null) return abs;
        try {
            cur = cur.toRealPath();
        } catch (IOException | RuntimeException e) {
            return abs;
        }
        return rest == null ? cur : cur.resolve(rest);
    }

    /** The refusal for {@link #sinkParseableUnderTarget} — writes NOTHING and exits 2 (the sink was never
     *  armed; the input exemption's own posture, because by expansion the path IS an input). */
    static void refuseSinkUnderTarget(String flag, String sink, String target) {
        if (!sinkParseableUnderTarget(sink, target)) return;
        System.err.println("candor: " + flag + " " + sink + " lies under the scan target " + target
                + " and ends in an extension this engine parses (.class/.jar/.zip) — the scan would read "
                + "the report back as a source file, and arming would destroy any real one at that path. "
                + "Refusing (exit 2); nothing was written. A report inside the tree is fine at a non-source "
                + "path — the recommended " + target + "/.candor/report.json layout stays permitted.");
        System.exit(2);
    }

    /** ⟨0.28⟩ Follow a chain of symlinks to the artifact finally named, target-need-not-exist. */
    static Path resolveSinkArtifact(Path p) {
        Path cur = p;
        for (int i = 0; i < 32; i++) {
            if (!Files.isSymbolicLink(cur)) return cur;
            try {
                Path t = Files.readSymbolicLink(cur);
                cur = t.isAbsolute() ? t
                        : (cur.getParent() == null ? t : cur.getParent().resolve(t));
            } catch (IOException e) {
                return cur;
            }
        }
        return cur;
    }

    /** Absolute, symlink-resolved as far as the filesystem allows — the parent when the leaf is absent. */
    private static Path resolveForCompare(Path p) throws IOException {
        Path abs = p.toAbsolutePath();
        Path parent = abs.getParent(), name = abs.getFileName();
        if (parent == null || name == null) return abs.normalize();
        Path base = Files.exists(parent) ? parent.toRealPath() : parent.normalize();
        return base.resolve(name);
    }

    /**
     * SPEC §3.3.1 ⟨0.27⟩ — refuse a {@code --gate-json} sink that names an INPUT of this run.
     *
     * <p>Arming writes to the path before the run knows its answer, so pointing it at the policy file
     * destroys the policy. Measured here before the guard existed: {@code --policy P --gate-json P} on
     * code that violates {@code deny Net} exited **0** with {@code "ok": true} — the JSON refusal
     * overwrote {@code P}, every line of it parsed as an unknown rule, and the gate ran over zero rules.
     * A machine-readable all-clear produced by deleting the question.
     *
     * <p>Writes NOTHING and exits 2. This is the one exempt cause in the arming rule, and it is exempt
     * because the path was never a sink: there is no verdict at it to go stale.
     */
    /**
     * SPEC §3.3.1 ⟨0.27⟩ — every path this run READS, whatever channel it arrived through.
     *
     * <p>THE FIRST VERSION OF THIS GUARD KEYED ON THE FLAG, and {@code Config}'s own ⟨0.24⟩ note says
     * why that is wrong, forty lines from where the check was written: <i>"a policy does not change what
     * it is according to how the operator handed it over; keying on the flag made the fail-open case the
     * one CI actually uses."</i> Measured: with the policy declared by {@code .candor/config} — which is
     * the checked-in form, i.e. the one a CI job has — {@code --gate-json <that policy>} destroyed it and
     * exited 0 with {@code "ok": true} in ALL FOUR ENGINES, because the pre-pass only ever looked at
     * {@code --policy} and {@code CANDOR_POLICY}.
     *
     * <p>The config is read LENIENTLY here — no exit, no diagnostic — because this runs before the real
     * config load and must not pre-empt its refusal. If the config cannot be read we simply learn
     * nothing from it; the load a moment later will fail loudly on its own terms. This read decides only
     * whether a path is an INPUT, never what the run does with it.
     */
    static java.util.List<String[]> runInputs(String target, String policyFlag) {
        var out = new java.util.ArrayList<String[]>();
        // ⟨0.28⟩ THE TARGET IS AN INPUT. SPEC §3.3.1 (3) lists "the target's own source tree" among the
        // paths arming must not touch, the CANDOR_DEPS note below says the scan target is an input too —
        // and the target was in neither list. Measured: `candor app.jar --json app.jar` overwrote the jar
        // with the fail-closed placeholder and then diagnosed its own act ("cannot read scan target
        // app.jar: zip END header not found") — the run destroyed the thing it was asked to scan, and
        // `--gate-json app.jar` destroyed it identically. EXACT artifact, not containment: a report
        // written into `.candor/` INSIDE the scanned tree is ordinary usage, and `sameArtifact` compares
        // the path the operator named, so that stays permitted while `--json <the target itself>` is
        // refused. Registered HERE so both sinks — and the sidecar remover — inherit it from the one list.
        if (target != null) out.add(new String[]{target, "the scan target"});
        if (policyFlag != null) out.add(new String[]{policyFlag, "--policy"});
        for (var e : new String[][]{{"CANDOR_POLICY", "CANDOR_POLICY"}, {"CANDOR_BASELINE", "CANDOR_BASELINE"},
                                    {"CANDOR_CONFIG", "CANDOR_CONFIG"}}) {
            String v = System.getenv(e[0]);
            if (v == null || v.isEmpty()) continue;
            // ⟨0.28⟩ THE BASELINE IS A REPORT LOCATOR, AND ITS LOADER READS THE PAIR. checkBaseline
            // loads `<stem>.callgraph.json` through Query.loadCallgraphSignalled — the ⟨0.16⟩
            // pure→effectful ratchet is answered FROM the sidecar — while this list carried only the
            // token the operator typed (SPEC §3.3.1 (3): "AND AN INPUT LOCATOR NAMES A SET — COMPARE
            // THE EXPANSION, NEVER THE TOKEN"). Measured on this engine 2026-08-12:
            //   CANDOR_BASELINE=base.json candor cls --json base.callgraph.json
            //     → the run wrote its report OVER the ratchet's sidecar (98 → 1180 bytes), then read
            //       the wreckage back and blamed it ("the baseline call-graph sidecar beside base.json
            //       is corrupt/unreadable") — exit 2 with the operator's baseline pair destroyed. The
            //       config `baseline` spelling destroyed it identically through --gate-json.
            if (e[0].equals("CANDOR_BASELINE")) addReportInput(out, v, e[1]);
            else out.add(new String[]{v, e[1]});
        }
        String deps = System.getenv("CANDOR_DEPS");
        if (deps != null) for (String d : deps.split("[" + java.io.File.pathSeparator + ",\\s]+"))
            if (!d.isEmpty()) {
                addReportInput(out, d, "a CANDOR_DEPS report");
                // A DIRECTORY DEP IS EVERY REPORT INSIDE IT — the loader walks it, so registering only
                // the DIRECTORY left those files unnamed and `--gate-json <depdir>/lib.json` destroyed
                // the operator's report. This engine printed a note that the clobbered file had no
                // `functions` and carried on at exit 0 regardless — the loudest of the four, and still
                // a green run over a destroyed input. Expanded HERE, not in `sameArtifact`: the scan
                // TARGET is an input too, and a verdict written into the scanned tree is ordinary.
                // `Files.walk`, matching Loader's own enumeration — NOT `Files.list`. The first repair
                // used the flat form beside the loader's RECURSIVE one, so a report a level down stayed
                // unguarded. A guard that enumerates differently from the loader guards a different set
                // of files, which is the whole defect one level in.
                try {
                    Path dp = Path.of(d);
                    if (Files.isDirectory(dp)) {
                        try (var st = Files.walk(dp)) {
                            st.filter(f -> f.toString().endsWith(".json"))
                              .forEach(f -> addReportInput(out, f.toString(), "a CANDOR_DEPS report"));
                        }
                    }
                } catch (IOException | RuntimeException ignored) { /* token itself is registered above */ }
            }
        // …AND THE CONFIG'S OWN KEYS, THROUGH THE ENGINE'S OWN LOADER.
        //
        // This used to re-derive the parse — walk for `.candor/config`, split each line, resolve values
        // against a directory computed here — and a review took it apart on exactly that. Three separate
        // holes, all from the SAME cause: a second parser that has to agree with the first and does not.
        //
        //   * the split was `"(?U)\s+"`. In a Java string literal `\s` is JEP-368's SPACE escape, so
        //     the regex was `(?U) +` — spaces only. A TAB-separated `policy` line was not recognised
        //     here while the real loader read it fine, so `--gate-json <that policy>` destroyed it and
        //     the run exited 0 with `"ok": true`.
        //   * the config's home directory was taken as parent-of-parent unconditionally; the real loader
        //     only steps out of a trailing `.candor/` segment. A `CANDOR_CONFIG` outside a `.candor` dir
        //     therefore resolved relative values one level too high, and the guard protected a path the
        //     run never reads.
        //   * `deps` was split on the path separator only, where the real loader splits on whitespace
        //     too, so a space-separated list registered as one unresolvable token and NO dep was covered.
        //
        // Calling the real loader is the fix for the class, not for the three instances. `load(path,
        // false)` is the LENIENT arm — it never exits — which matters because this runs before the real
        // config load and must not pre-empt its refusal, and its values are already anchor-resolved.
        try {
            Path cfg = null;
            String override = System.getenv("CANDOR_CONFIG");
            if (override != null) { Path o = Path.of(override); if (Files.isRegularFile(o)) cfg = o; }
            if (cfg == null) cfg = Config.discover(Path.of(target));
            if (cfg != null) {
                out.add(new String[]{cfg.toString(), "the discovered .candor/config"});
                Config c = Config.load(cfg, false);
                for (var e : c.valuesView().entrySet()) {
                    String key = e.getKey(), val = e.getValue();
                    if (val == null || val.isEmpty()) continue;
                    if (key.equals("policy")) {
                        out.add(new String[]{val, "the config's `policy`"});
                    } else if (key.equals("baseline")) {
                        // The config spelling of CANDOR_BASELINE — SPEC records that a policy declared
                        // via `.candor/config` rather than a flag was the spelling that defeated the
                        // FIRST version of this guard in all four engines, so the sidecar expansion
                        // rides BOTH spellings, not the one in front of the author.
                        addReportInput(out, val, "the config's `baseline`");
                    } else if (key.equals("deps")) {
                        // already anchor-resolved and joined on the path separator by the loader
                        for (String one : val.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator)))
                            if (!one.isEmpty()) addReportInput(out, one, "the config's `deps`");
                    }
                }
            }
        } catch (RuntimeException e) {
            // Lenient by design: a config this cannot read teaches the guard nothing, and the real load a
            // moment later fails on its own terms.
        }
        return out;
    }

    /**
     * ⟨0.28⟩ Register a report-shaped input PLUS its on-disk §2.2 sidecars — SPEC §3.3.1 (3), "THE
     * SIDECARS EXPAND TOO": a report locator that resolves to {@code <stem>.json} also reaches
     * {@code <stem>.callgraph.json} and the rest of the reserved family, and a guard that protects the
     * report and not its sidecars leaves the pair destroyable one half at a time. The stem arithmetic is
     * the same one {@code ReportWriter#writeCallgraph} and {@link Query#loadCallgraphSignalled} use
     * (trailing {@code .json} dropped if present), and the segment list is
     * {@link Loader#reportSidecarSegments()} — the engine's ONE list, which is also where the {@code
     * gate} exclusion lives ({@code <stem>.gate.json} is the verdict sink's own beside-the-report
     * layout and must stay a permitted sink). EXISTING regular files only: the guard protects data, and
     * a sidecar not on disk has none to lose — the same boundary {@code Query.gateReportInputFiles}
     * draws for the query-side twin of this list.
     */
    static void addReportInput(java.util.List<String[]> out, String path, String label) {
        out.add(new String[]{path, label});
        String stem = path.endsWith(".json") ? path.substring(0, path.length() - 5) : path;
        for (String seg : Loader.reportSidecarSegments()) {
            String side = stem + "." + seg + ".json";
            try {
                if (Files.isRegularFile(Path.of(side)))
                    out.add(new String[]{side, "the §2.2 `" + seg + "` sidecar of " + label + " " + path});
            } catch (RuntimeException ignored) { /* not a path on this filesystem — nothing to protect */ }
        }
    }

    /** Refuse the sink if it names ANY input of this run, whatever channel that input arrived through. */
    /** ⟨0.28⟩ Is this sink an input? Non-exiting, so the duplicate path can ask without taking the run
     *  down — the exemption covers the offending PATH, and the other sinks still have readers. */
    static boolean gateJsonIsInput(String gateJson, String target, String policyFlag) {
        if (gateJson == null || gateJson.equals("-")) return false;
        // ⟨0.28⟩ a sink under the target with a parseable extension IS an input, by the target's expansion.
        if (sinkParseableUnderTarget(gateJson, target)) return true;
        for (String[] in : runInputs(target, policyFlag))
            if (in[0] != null && sameArtifact(gateJson, in[0])) return true;
        return gateJsonIsAtConfig(gateJson);
    }

    static void refuseGateJsonOverAnyInput(String gateJson, String target, String policyFlag) {
        if (gateJson == null || gateJson.equals("-")) return;
        for (String[] in : runInputs(target, policyFlag)) refuseGateJsonOverInput(gateJson, in[0], in[1]);
        // ⟨0.28⟩ the target's EXPANSION — see #sinkParseableUnderTarget; a rule bound to one sink and not
        // its sibling is the recurring defect this rung keeps paying for.
        refuseSinkUnderTarget("--gate-json", gateJson, target);
        refuseGateJsonAtConfig(gateJson);
    }

    static void refuseGateJsonOverInput(String gateJson, String other, String flag) {
        if (!sameArtifact(gateJson, other)) return;
        System.err.println("candor: --gate-json " + gateJson + " names the same file as " + flag + " "
                + other + " — writing the verdict there would destroy the input this run reads. "
                + "Nothing was written; give --gate-json a different path.");
        System.exit(2);
    }

    /**
     * SPEC §3.3.1 ⟨0.27⟩ — `.candor/config` is never a verdict sink, wherever it is.
     *
     * <p>The per-input checks above can only name inputs the run has already been TOLD about, and the
     * config is DISCOVERED by walking up from the target — so by the time its path is known, arming has
     * already destroyed it. Measured on candor-swift: `--gate-json <target>/.candor/config` deleted the
     * config that declared the policy, and the run then exited 0 with no gate at all.
     *
     * <p>This is a check on the SHAPE rather than on a discovered path, deliberately: it needs no
     * discovery, so it can run before the first write, and it covers a config found anywhere up the
     * tree. There is no legitimate run that writes a gate verdict to a file named `config` inside a
     * `.candor` directory.
     */
    /** The SHAPE test alone, so the refusing and the probing form share one copy. */
    static boolean gateJsonIsAtConfig(String gateJson) {
        if (gateJson == null || gateJson.equals("-")) return false;
        Path p = Path.of(gateJson).toAbsolutePath().normalize();
        Path parent = p.getParent(), name = p.getFileName();
        if (name == null || parent == null || parent.getFileName() == null) return false;
        return name.toString().equals("config") && parent.getFileName().toString().equals(".candor");
    }

    static void refuseGateJsonAtConfig(String gateJson) {
        if (!gateJsonIsAtConfig(gateJson)) return;
        System.err.println("candor: --gate-json " + gateJson + " is a .candor/config — refusing (exit 2). "
                + "The verdict is armed before the config is read, so this would destroy the config that "
                + "configures this run. Nothing was written; give the verdict its own path.");
        System.exit(2);
    }

    /**
     * ⟨0.28⟩ SPEC §3.3.1 (3) — a {@code --json <file>} sink that names an INPUT of this run is refused
     * having written NOTHING to that path. Arming (below) writes before the run knows its answer, so
     * pointing the sink at the policy or the discovered {@code .candor/config} would destroy the input
     * this run reads — the exact defect the verdict-sink twin exists to prevent, on the report sink one
     * hop upstream. Reuses {@link #runInputs} and {@link #sameArtifact} so the input set and the
     * artifact resolution can never disagree between the two sinks.
     */
    static void refuseJsonOverAnyInput(String jsonFile, String target, String policyFlag) {
        if (jsonFile == null || jsonFile.equals("-")) return;
        java.util.List<String[]> inputs = runInputs(target, policyFlag);
        for (String[] in : inputs) refuseJsonOverInput(jsonFile, in[0], in[1]);
        refuseSinkUnderTarget("--json", jsonFile, target);
        // ⟨0.28⟩ THE SINK EXPANDS TOO — the report sink is a SET, not one file. A file-mode `--json
        // <out>` also writes `<stem>.callgraph.json` / `<stem>.hierarchy.json` (and arming deletes the
        // whole reserved family at that stem), so comparing only the token the operator typed leaves
        // every collision between the sink's OWN sidecars and an input unguarded. Measured on this
        // engine 2026-08-12 — the exact defect candor-scan fixed as `baseline_artifact_files`
        // (`CANDOR_BASELINE=base … --out base`), one spelling over:
        //   CANDOR_BASELINE=base.json candor cls --json base
        //     → the run wrote `base` and REPLACED the ratchet's `base.callgraph.json` with the CURRENT
        //       call graph (98 → 138 bytes) at a success exit — the pure→effectful baseline silently
        //       half-updated, so the next run gates against a sidecar the baseline never produced.
        String stem = jsonFile.endsWith(".json") ? jsonFile.substring(0, jsonFile.length() - 5) : jsonFile;
        for (String seg : Loader.reportSidecarSegments()) {
            String side = stem + "." + seg + ".json";
            for (String[] in : inputs) {
                if (in[0] == null || !sameArtifact(side, in[0])) continue;
                System.err.println("candor: --json " + jsonFile + " also writes its §2.2 sidecar " + side
                        + ", which names the same file as " + in[1] + " " + in[0]
                        + " — writing the report set there would destroy the input this run reads. "
                        + "Nothing was written; give --json a different path.");
                System.exit(2);
            }
        }
        refuseJsonAtConfig(jsonFile);
    }

    static void refuseJsonOverInput(String jsonFile, String other, String flag) {
        if (!sameArtifact(jsonFile, other)) return;
        System.err.println("candor: --json " + jsonFile + " names the same file as " + flag + " "
                + other + " — writing the report there would destroy the input this run reads. "
                + "Nothing was written; give --json a different path.");
        System.exit(2);
    }

    static void refuseJsonAtConfig(String jsonFile) {
        if (!gateJsonIsAtConfig(jsonFile)) return;  // shape test is generic — .candor/config is never a sink
        System.err.println("candor: --json " + jsonFile + " is a .candor/config — refusing (exit 2). "
                + "The report is armed before the config is read, so this would destroy the config that "
                + "configures this run. Nothing was written; give the report its own path.");
        System.exit(2);
    }

    /**
     * ⟨0.28⟩ SPEC §3.3.1 (1)+(2) — <b>ARM THE REPORT SINK.</b> Mirror of {@link #armGateJson} for the
     * report sink one hop upstream: write the ⟨0.21⟩ Row-1 fail-closed manifest-carrying empty at the
     * instant the sink is known, before anything else can exit. Every subsequent exit then leaves that
     * document in place unless {@link ReportWriter#writeJson}'s atomic write replaces it with a real
     * report. Without this, a scan that exits 2 (unknown flag, unreadable config, target missing) left
     * the previous run's report BYTE-IDENTICAL on disk — measured on this engine 2026-08-10, 648 bytes
     * unchanged before and after — and a downstream {@code gate --report <that>} then went green over a
     * document the failed run never produced.
     *
     * <p>The shape is exactly what a ⟨0.24⟩ consumer already reads as "not covered, no purity licence":
     * {@code functions: []} plus {@code analyzed.count: 0} plus {@code unanalyzed} naming the run. No new
     * reader logic — the naive read of what a report emits has to be the safe one.
     *
     * <p>⟨0.28⟩ <b>And the report's §2.2 sidecars go with it</b> — see
     * {@link #removeArmedReportSidecars}. Arming and removing are ONE act, which is why the removal lives
     * inside this method rather than beside its call site: an armed report with a live sidecar is the
     * pair the rung exists to prevent, and a second call site is a second chance to forget.
     */
    static void armReportJson(String path, String target, String policyFlag) {
        if (path == null || path.equals("-")) return;
        String[] prov = ReportWriter.provenance();
        var candor = new java.util.LinkedHashMap<String, Object>();
        candor.put("version", prov[0]);
        candor.put("toolchain", prov[1]);
        candor.put("spec", SPEC_VERSION);
        var analyzed = new java.util.LinkedHashMap<String, Object>();
        analyzed.put("count", 0);
        var un = new java.util.LinkedHashMap<String, Object>();
        un.put("path", "<run>");
        un.put("reason", "armed: the scan did not complete — this document was written when the run "
                + "STARTED and was never replaced by a real report, so the run failed, crashed or was "
                + "killed before it could decide. It is NOT a claim about the code; see the run's stderr "
                + "for the cause.");
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("candor", candor);
        out.put("functions", new java.util.ArrayList<>());
        out.put("analyzed", analyzed);
        out.put("unanalyzed", java.util.List.of(un));
        try {
            Files.writeString(Path.of(path), io.poly.candor.model.ReportJson.pretty(out) + "\n");
        } catch (IOException | RuntimeException e) {
            System.err.println("candor: could not arm --json " + path + " fail-closed ("
                    + e.getMessage() + ") — if this run does not complete, that path may still hold a "
                    + "PREVIOUS run's report");
            // ARMING FAILED, SO THE SIDECARS STAY. The rule is "no live sidecar beside an ARMED report";
            // this path still holds the PREVIOUS run's report, so removing its sidecars would produce a
            // stale report with no call graph — a pair no run has ever written, and strictly worse than
            // the pre-rung state this failure has left in place. (Deliberately unlike the rust reference,
            // which ignores the write result; java can see the failure, so it acts on it.)
            return;
        }
        removeArmedReportSidecars(path, target, policyFlag);
    }

    /**
     * ⟨0.28⟩ SPEC §3.3.1 — <b>THE §2.2 SIDECARS GO WITH THE ARMED REPORT, DELETED NOT EMPTIED.</b>
     *
     * <p>An armed report beside a LIVE sidecar is a pair that contradicts itself, and §2.2 gives the
     * sidecar no provenance of its own to arbitrate with. Not theoretical on this engine:
     * {@code callers}/{@code whatif}/{@code rewire} are answered FROM the {@code .callgraph.json}
     * sidecar, because a currently-pure function is absent from the report by §2 rule 3 and only the
     * sidecar records it. MEASURED here 2026-08-11 — baseline {@code App.f} pure, reached by {@code g}
     * (and {@code main}); the new version gives {@code f} an effect and adds a caller {@code h}; the run
     * exits 2 on an unknown flag with the report armed:
     *
     * <pre>  callers f → exit 0, "`App.f` is reached by 2 function(s)
     *                       (the blast radius if it gained an effect): App.g, App.main"</pre>
     *
     * Confident, exit-0, labelled the blast radius, and WRONG — {@code h} calls {@code f} too. An agent
     * reads it as safe-to-edit. That is the cardinal sin, reached through the half of the pair the
     * report-arming rung had not touched.
     *
     * <p><b>Deleted rather than {@code {}}</b>, and NOT by reading the report's own anti-deletion rule
     * across: §3.3.1 forbids deleting a REPORT because a consumer that reads a missing file as "nothing
     * to report" fails open, and no sidecar consumer has that failure mode — §2.2 makes the sidecar
     * OPTIONAL, so every consumer was forced to define an absence arm from the start and every specified
     * arm is safe. ⟨0.24⟩ has already ruled an empty, an absent and an unparseable HIERARCHY sidecar to
     * be the same input, and the one cell that rule does not cover — an empty-but-valid baseline
     * CALLGRAPH — was measured four-way to answer {@code origin: "unknown"} on all four engines. So
     * {@code {}} buys nothing deletion does not, and absence is the state the consumers were built for.
     *
     * <p><b>The guess runs the OPPOSITE way from the armer's, on purpose.</b> {@link #armReportJson}
     * writes only a path the operator named, because there a miss leaves a stale report and an over-reach
     * destroys a file. Here a miss merely leaves a sidecar behind — the pre-rung state, and the ⟨0.28⟩
     * pairing rule catches it consumer-side — while an over-reach would delete something that is not
     * ours. So this identifies by the §2.2 RESERVED SEGMENT NAMES, scoped to this one report's stem —
     * asked of {@link Loader#reportSidecarSegments()}, the engine's ONE list, which also carries the
     * argument for the one segment it withholds ({@code gate}, the verdict sink's own document).
     * Both directions are chosen so the WRONG guess costs the least.
     *
     * <p><b>The input exemption applies here too</b> ((3): the exemption covers the PATH, not the run).
     * A sidecar path that is also an input of this run — a chained {@code CANDOR_DEPS} report's own
     * sidecar living under the report's stem, say — is left alone and the operator is told, because
     * <i>do not touch what this run reads</i> outranks the pairing invariant. {@link #runInputs} is
     * asked ONCE and {@link #sameArtifact} does the comparing, so this can never disagree with the two
     * sink guards about what an input is.
     */
    static void removeArmedReportSidecars(String path, String target, String policyFlag) {
        if (path == null || path.equals("-")) return;
        // The same stem arithmetic ReportWriter#writeCallgraph/#writeHierarchy use to CHOOSE these names,
        // trailing `.json` dropped if present — so the set removed is exactly the set a clean run writes.
        String stem = path.endsWith(".json") ? path.substring(0, path.length() - 5) : path;
        java.util.List<String[]> inputs = null;
        for (String seg : Loader.reportSidecarSegments()) {
            String side = stem + "." + seg + ".json";
            Path sp;
            try {
                sp = Path.of(side);
                if (!Files.exists(sp)) continue;
            } catch (RuntimeException e) { continue; }   // not even a path on this filesystem
            // A SYMLINKED sidecar is LEFT ALONE (the family ruling; rust and swift already hold it). The
            // link is the OPERATOR'S layout, not this run's artifact: `deleteIfExists` here removed the
            // LINK while the stale data stayed readable under the target's other name — the layout
            // severed, the hazard intact. Deleting the TARGET instead reaches outside the report's stem
            // and destroys a file that may have other readers. And even the benign-looking cycle —
            // delete, scan, rewrite by bytes — converts a link into a regular file on the SUCCESS path.
            // None of those is ours to do, so this discloses the pair and moves on, the same posture as
            // the input-exempt arm below: an armed report makes its sidecar unanswerable either way.
            if (Files.isSymbolicLink(sp)) {
                System.err.println("candor: " + side + " is a SYMLINK and a §2.2 sidecar of the armed "
                        + "report --json " + path + " — leaving the link in place (it is the operator's "
                        + "layout, and what it points at may have other readers). Treat it as "
                        + "unanswerable: an armed report makes its sidecar describe a PREVIOUS run.");
                continue;
            }
            if (inputs == null) inputs = runInputs(target, policyFlag);   // once, and only if there is work
            String reads = null;
            for (String[] in : inputs)
                if (in[0] != null && sameArtifact(side, in[0])) { reads = in[1]; break; }
            if (reads != null) {
                System.err.println("candor: " + side + " is a §2.2 sidecar of the armed report --json "
                        + path + " AND names " + reads + ", an INPUT of this run — leaving it in place. "
                        + "Read it together with that report (an armed report makes its sidecar "
                        + "unanswerable, whatever the sidecar says).");
                continue;
            }
            try {
                Files.deleteIfExists(sp);
            } catch (IOException | RuntimeException e) {
                System.err.println("candor: could not remove " + side + ", the §2.2 sidecar of the armed "
                        + "report --json " + path + " (" + e.getMessage() + ") — it now sits beside a "
                        + "fail-closed report and describes a PREVIOUS run. Delete it, or ignore it: a "
                        + "sidecar whose report is a manifest-carrying empty is unanswerable input.");
            }
        }
    }

    /** Has a gate document (verdict or refusal) been emitted by this run? Consulted only by the
     *  stream-sink shutdown hook below; set by {@link #writeGateJson} and {@link #writeRefusedGateJson}. */
    static volatile boolean gateDocEmitted = false;

    /** ⟨0.28⟩ Has a REPORT document been emitted to stdout by this run? Consulted only by the
     *  {@link #armReportStream} shutdown hook; set by {@link ReportWriter#writeJson} on the {@code "-"}
     *  branch so a completed {@code --json} stdout print isn't followed by a fail-closed placeholder. */
    static volatile boolean reportDocEmitted = false;

    /**
     * ⟨0.27⟩ <b>THE STREAM SINK GETS THE FAIL-CLOSED DOCUMENT ON EVERY EXIT-2 CAUSE TOO — SPEC §3.1's
     * stream-sink clause.</b> {@code --gate-json -} cannot be ARMED: a stream has no previous document to
     * go stale, and a placeholder would put two documents in a consumer's pipe. But the
     * document-on-every-exit rule applies in full, and this engine had quietly re-created the
     * write-nothing carve-out on the stream, selected by CAUSE: an unhonourable policy wrote the refusal
     * to stdout while an unknown flag exited 2 leaving stdout EMPTY — the same operator mistake, answered
     * or not according to which early exit fired. An empty stream throws the consumer back to scraping
     * stderr, the distinction that made the incomplete-analysis defect a defect.
     *
     * <p>A shutdown hook rather than a write at each exit site, for the same reason {@link #armGateJson}
     * is not threaded into twenty {@code System.exit(2)} calls: the rule is over the RUN, not over the
     * sites anyone enumerated. Every completed gate run writes its document through
     * {@link #writeGateJson}/{@link #writeRefusedGateJson} (which set {@link #gateDocEmitted}), so the
     * hook fires exactly on the runs that exited before a verdict existed — and stdout then carries one
     * fail-closed refusal as its only content, keeping §3.3's pure-JSON rule.
     */
    static void armGateJsonStream() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (gateDocEmitted) return;
            var out = new java.util.LinkedHashMap<String, Object>();
            out.put("spec", SPEC_VERSION);
            out.put("ok", false);
            out.put("refused", true);
            out.put("reason", "the gate did not complete — this run exited before a verdict could be "
                    + "decided (a broken gate config, an unknown flag, or a crash). It is NOT a verdict "
                    + "about the code; see the run's stderr for the cause.");
            System.out.println(io.poly.candor.model.ReportJson.pretty(out));
            System.out.flush();
        }));
    }

    /**
     * ⟨0.28⟩ <b>THE REPORT STREAM SINK GETS THE FAIL-CLOSED DOCUMENT ON EVERY EXIT-2 CAUSE TOO — SPEC
     * §3.3.1 (4).</b> Mirror of {@link #armGateJsonStream} for the report stream, one hop upstream.
     * Measured on this engine 2026-08-10: {@code candor <target> --json --zzz-not-a-flag} exited 2 with
     * <b>stdout empty</b>; a downstream JSON consumer keying on stdout throws a parse error and is thrown
     * back to scraping stderr — the exact distinction that made the incomplete-analysis defect a defect.
     *
     * <p>The shape is the ⟨0.21⟩ Row-1 manifest-carrying empty: {@code functions: []} plus
     * {@code analyzed.count: 0} plus {@code unanalyzed} naming the run itself as un-analyzable. A ⟨0.24⟩
     * consumer already reads that combination as "no purity licence" — no new reader logic is needed. The
     * naive read of what a report format emits has to be the safe one; here that is FAIL.
     *
     * <p>A shutdown hook rather than a write threaded through every one of the ~30 {@code System.exit(2)}
     * sites, for the same reason {@link #armGateJsonStream} is: the rule is over the RUN, not over the
     * sites anyone enumerated (a crash, an OOM, a future exit path). The successful stdout print in
     * {@link ReportWriter#writeJson} sets {@link #reportDocEmitted}, so the hook fires exactly on the
     * runs that exited before a report existed.
     *
     * <p>Not installed when {@code --gate-json -} is also on the command line: that stream is already
     * claimed by the verdict document (or by the two-stream refusal doc), and a second write from this
     * hook would put two JSON documents on one pipe — the shape §3.3's stream refusal exists to prevent.
     */
    static void armReportStream() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (reportDocEmitted) return;
            String[] prov = ReportWriter.provenance();
            var candor = new java.util.LinkedHashMap<String, Object>();
            candor.put("version", prov[0]);
            candor.put("toolchain", prov[1]);
            candor.put("spec", SPEC_VERSION);
            var analyzed = new java.util.LinkedHashMap<String, Object>();
            analyzed.put("count", 0);
            var un = new java.util.LinkedHashMap<String, Object>();
            un.put("path", "<run>");
            un.put("reason", "refused: the report did not complete — this run exited before a scan "
                    + "could produce one (a broken flag, unreadable input, misconfiguration, or a crash). "
                    + "It is NOT a claim the code is pure; see the run's stderr for the cause.");
            var envelope = new java.util.LinkedHashMap<String, Object>();
            envelope.put("candor", candor);
            envelope.put("functions", java.util.List.of());
            envelope.put("analyzed", analyzed);
            envelope.put("unanalyzed", java.util.List.of(un));
            System.out.println(io.poly.candor.model.ReportJson.pretty(envelope));
            System.out.flush();
        }));
    }

    /** ⟨0.31⟩ The `--gate-json` file this run armed, so a later refusal can replace its stub in place.
     *  Remembered here rather than threaded through: the refusal sites are deep in `main` and the sink
     *  is decided during pre-parse, and passing it down four call layers to reach them is how one of the
     *  sites gets missed. */
    private static String ARMED_GATE_JSON = null;

    /** ⟨0.31⟩ Replace the ARMING STUB with the real reason when this run DECIDES to refuse.
     *
     *  <p>{@link #armGateJson} writes a stub saying the run "failed, crashed or was killed" — correct
     *  while the run's fate is unknown, and FALSE the moment it deliberately refuses. MEASURED: a target
     *  holding no {@code .class} exited 2 with excellent stderr (this engine's remedy is the family's
     *  model) while its {@code --gate-json} document still described a crash. A machine consumer reads
     *  only that document, and ⟨0.24⟩ pins its {@code reason} as a string NAMING THE CAUSE — this family
     *  rates a false description worse than a missing one, because it sends the reader after a crash
     *  that never happened.
     *
     *  <p>The remedy travels IN the reason, for the same audience: whoever reads the document is exactly
     *  whoever cannot go and look at stderr. */
    /** ⟨0.31⟩ The cause of a refusal this run DECIDED, if it decided one — read by the file-sink
     *  shutdown hook so a deliberate refusal is not described as a crash. Null means the run either
     *  completed or died without deciding, and the hook says exactly that instead of guessing. */
    static volatile String decidedRefusal = null;

    static void refuseGateJson(String why) {
        decidedRefusal = why;
        String path = ARMED_GATE_JSON;
        if (path == null || path.equals("-")) return;
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("spec", SPEC_VERSION);
        out.put("ok", false);
        out.put("refused", true);
        out.put("reason", why);
        try {
            Files.writeString(Path.of(path), io.poly.candor.model.ReportJson.pretty(out) + "\n");
        } catch (IOException | RuntimeException e) {
            System.err.println("candor: could not write the refusal to --gate-json " + path
                    + " (" + e.getMessage() + ") — that path may still hold this run's arming stub");
        }
    }

    /** ⟨0.31⟩ THE FILE SINK GETS THE SAME SHUTDOWN HOOK THE STREAM SINK HAS HAD SINCE ⟨0.28⟩.
     *
     *  <p>{@link #armGateJsonStream} states the principle: "a shutdown hook rather than a write at each
     *  exit site … the rule is over the RUN, not over the sites anyone enumerated." The stream sink
     *  followed it; the FILE sink did not, and the gap shows — this class has <b>37 raw
     *  {@code System.exit(2)} calls</b> against 3 that write a refusal document, so on 37 paths the file
     *  sink keeps the ARMING STUB.
     *
     *  <p>That stub is a guess made before the run started: "the run failed, crashed or was killed before
     *  it could decide". For a crash that is right. For a deliberate refusal it is false, and ⟨0.24⟩ pins
     *  this field as a string NAMING the cause — a wrong one sends the operator after a failure that
     *  never happened.
     *
     *  <p>The hook knows one thing the stub cannot: the run is OVER. So it replaces the guess with a
     *  fact, and with the decided cause when {@link #decidedRefusal} holds one. Enumerating exit sites
     *  was considered and rejected for the reason quoted above — the next one added would be missed. */
    private static void armGateJsonFileHook(String path) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (gateDocEmitted) return;                      // a real verdict was written; leave it
            try {
                String now = Files.readString(Path.of(path));
                if (!now.contains("\"refused\": true")) return;   // not our document — never clobber it
                if (decidedRefusal == null && !now.contains("written when the run STARTED")) return;
            } catch (IOException | RuntimeException e) {
                return;   // unreadable: leave whatever is there rather than guess
            }
            var out = new java.util.LinkedHashMap<String, Object>();
            out.put("spec", SPEC_VERSION);
            out.put("ok", false);
            out.put("refused", true);
            out.put("reason", decidedRefusal != null ? decidedRefusal
                    : "the gate did not complete — this run EXITED before a verdict could be decided. "
                    + "It is NOT a verdict about the code; see the run's stderr for the cause.");
            try {
                Files.writeString(Path.of(path), io.poly.candor.model.ReportJson.pretty(out) + "\n");
            } catch (IOException | RuntimeException e) {
                // the armed stub stands — still fail-closed, just less specific
            }
        }));
    }

    static void armGateJson(String path) {
        if (path == null || path.equals("-")) return;
        ARMED_GATE_JSON = path;
        armGateJsonFileHook(path);
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("spec", SPEC_VERSION);
        out.put("ok", false);
        out.put("refused", true);
        out.put("reason", "the gate did not complete — this document was written when the run STARTED and "
                + "was never replaced by a verdict, so the run failed, crashed or was killed before it "
                + "could decide. It is NOT a verdict about the code; see the run's stderr for the cause.");
        try {
            Files.writeString(Path.of(path), io.poly.candor.model.ReportJson.pretty(out) + "\n");
        } catch (IOException | RuntimeException e) {
            System.err.println("candor: could not arm --gate-json " + path + " fail-closed ("
                    + e.getMessage() + ") — if this run does not complete, that path may still hold a "
                    + "PREVIOUS run's verdict");
        }
    }

    /**
     * ⟨0.24⟩ SPEC §3.1 — the POLICY VOCABULARY config for a run, anchored at the RESOLVED policy path
     * whichever channel supplied it ({@code --policy}, {@code CANDOR_POLICY}, or the config `policy` key).
     * Falls back to the target's config only when there is no policy at all, so the aliases a
     * {@code parsepolicy} witness would report and the ones the GATE expands are read from one file.
     *
     * <p>A path this machine cannot even turn into a {@code Path} is not diagnosed here — the gate is about
     * to read the same string and will fail loudly and specifically on it (the unreadable-policy posture).
     * Falling back to the target's config in the meantime would be the anchor bug in miniature, so the
     * fallback is an EMPTY vocabulary: no aliases resolve, and the policy's own failure is what the
     * operator sees.
     */
    static Config policyVocabularyFor(String policyPath, Config targetConfig) {
        if (policyPath == null || policyPath.isEmpty()) return targetConfig;
        try {
            return Config.policyVocabulary(Path.of(policyPath));
        } catch (java.nio.file.InvalidPathException e) {
            return Config.empty();
        }
    }

    /**
     * ⟨0.24⟩ <b>A REFUSAL MUST STILL WRITE A DOCUMENT — SPEC §3.1.</b> A gate that refuses used to write
     * no {@code --gate-json} file at all, so a CI wrapper that reads the path unconditionally re-read
     * <b>the PREVIOUS run's document as current</b>. A green file from yesterday's clean run, still on
     * disk, is how a refusal becomes an all-clear. Deleting the path is not the fix either: a consumer
     * that treats a missing file as "nothing to report" fails open by a different route.
     *
     * <p>So the document is written, and it is <b>fail-closed to a NAIVE reader</b>: {@code ok: false}
     * plus {@code refused: true} and the reason. A consumer keying only on {@code ok} lands on FAIL; one
     * keying on {@code refused} learns why. Same reasoning as the empty-report rung — the naive read of a
     * document this format emits has to be the safe one, because the naive read is the one that ships.
     *
     * <p><b>It carries NO {@code violations} key.</b> Not an empty array: the gate is making no claim
     * about violations, and {@code "violations": []} is precisely the claim it cannot make. That is the
     * whole difference between "I found nothing" and "I could not look", and it is the difference a
     * machine consumer has to be able to see.
     *
     * <p>No {@code analyzed} either, for the same reason — on the whole-policy refusals the reports are
     * not even opened, and a count would describe a universe the verdict says nothing about.
     */
    static void writeRefusedGateJson(String path, String reason, java.util.List<String[]> unevaluated) {
        if (path == null) return;
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("spec", SPEC_VERSION);
        out.put("ok", false);
        out.put("refused", true);
        out.put("reason", reason);
        policyVocabularyJson(out);   // a refusal can be CAUSED by the vocabulary too — name the file
        if (!unevaluated.isEmpty()) out.put("unevaluated", unevaluatedJson(unevaluated));
        try {
            String json = io.poly.candor.model.ReportJson.pretty(out);
            if (path.equals("-")) System.out.println(json);
            else Files.writeString(Path.of(path), json + "\n");
            gateDocEmitted = true;   // the stream-sink hook must not add a second document
        } catch (IOException e) {
            // The caller is already exiting 2; say why the document is missing so the stale-file hazard
            // this method exists to close is at least AUDIBLE when the write itself fails.
            System.err.println("candor: could not write the refusal verdict to --gate-json " + path
                    + ": " + e.getMessage() + " — a consumer reading that path will see a STALE document");
        }
    }

    /**
     * ⟨0.24⟩ <b>THE AMBIENCE MUST BE DISCLOSED — SPEC §3.1.</b> If a config file supplied POLICY VOCABULARY
     * that participated in the verdict, the {@code --gate-json} document MUST name that file. §3.1's MUST
     * NOT lists three channels an effect must never enter a gate through; {@code .candor/config}'s
     * {@code unknown-alias} is the fourth, and it is the one no engine's test covered. Config discovery
     * walks PARENT directories and {@code CANDOR_CONFIG} overrides it entirely, so an alias file the
     * operator never named can be what decides the verdict — and the measured harm was a GREEN one, so the
     * disclosure fires on any alias a rule REFERENCED, not only on one that fired.
     *
     * <p>The remedy is the usual one here: not to forbid the input, but to make it impossible for it to act
     * unnamed. Omitted entirely when no alias was used, so every verdict without one is byte-identical to
     * a pre-⟨0.24⟩ one — and identical across the two routes, which is the point (both anchor at the policy
     * file now, so both name the same file).
     *
     * <p>⟨0.24⟩ <b>{@code aliases} MAPS EACH ALIAS TO THE CLASSES IT EXPANDS TO — an OBJECT, not an array</b>
     * (candor-spec {@code 7f5b5ba}). This engine shipped {@code ["corp"]}; candor-ts shipped
     * {@code {"corp": ["reflect"]}} and won the argument from THIS SECTION'S OWN SENTENCE rather than on a
     * headcount. §3.1 rejects {@code configSources: [path]} because <i>a disclosure that names the source but
     * not the content leaves the reader knowing they were affected and not how</i> — and {@code
     * aliases: ["corp"]} fails that same test one level down. <b>{@code corp = reflect} and
     * {@code corp = reflect,native} gate DIFFERENTLY under one unchanged policy line</b>, so a reader given
     * only the NAME cannot tell which gate ran; the name is exactly the part that did not change. The object
     * is a strict superset — {@code Object.keys} recovers the array a consumer had.
     *
     * <p>The class tokens are SORTED, so two configs declaring the same expansion in different orders
     * disclose the same bytes; {@code config} keeps its position and its meaning, since the content the
     * object adds is in addition to the source, not instead of it.
     */
    /** ⟨0.31⟩ The ambient `net-partner` declaration that MOVED a classification, for the VERDICT — a LIST
     *  of {@code {config, hosts}} records, matching the shape candor-ts and candor-rust emit (a
     *  {@code --report} prefix can match several reports, so the verdict key is a list even though one
     *  report carries one record).
     *
     *  <p>Omitted when nothing participated, so every verdict without ambient partner vocabulary stays
     *  byte-identical. Same position on both routes, because §3.1 makes byte-equality between the scan
     *  verdict and the `gate --report` verdict the acceptance test. */
    static void netPartnersJson(java.util.LinkedHashMap<String, Object> out) {
        if (ctx().netPartnersSource == null || ctx().netPartnersUsed.isEmpty()) return;
        var rec = new java.util.LinkedHashMap<String, Object>();
        rec.put("config", ctx().netPartnersSource);
        rec.put("hosts", new java.util.ArrayList<>(ctx().netPartnersUsed));
        out.put("netPartners", java.util.List.of(rec));
    }

    static void policyVocabularyJson(java.util.LinkedHashMap<String, Object> out) {
        if (ctx().vocabularySource == null || ctx().vocabularyUsed.isEmpty()) return;
        var v = new java.util.LinkedHashMap<String, Object>();
        v.put("config", ctx().vocabularySource);
        // Key order = `vocabularyUsed`'s (a TreeSet, so codepoint order — locale-independent, ⟨0.24⟩).
        var aliases = new java.util.LinkedHashMap<String, Object>();
        for (String name : ctx().vocabularyUsed) {
            // The alias is in the map by construction: `vocabularyUsed` is only added to on the branch that
            // RESOLVED it (Policy line ~1050). getOrDefault rather than get so a future caller that records
            // a use without a definition cannot NPE the whole verdict document out of existence.
            var classes = ctx().unknownAliases.getOrDefault(name, java.util.Set.of());
            aliases.put(name, classes.stream().map(io.poly.candor.model.ReasonClass::token).sorted().toList());
        }
        v.put("aliases", aliases);
        out.put("policyVocabulary", v);
    }

    /** {@code [{rule, why}, …]} — the wire shape of an unevaluated rule, shared by the violation document
     *  and (⟨0.24⟩) the refusal one, so a consumer parses one shape. */
    static List<Map<String, Object>> unevaluatedJson(java.util.List<String[]> unevaluated) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (String[] u : unevaluated) {
            var m = new java.util.LinkedHashMap<String, Object>();
            m.put("rule", u[0]);
            m.put("why", u[1]);
            rows.add(m);
        }
        return rows;
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
        // S3 TRANSFERS THAT NAME A LOCAL FILE ALSO TOUCH THE FILESYSTEM — Net was never the whole answer.
        // `s3.getObject(GetObjectRequest, File)` / `TransferManager.download(...)` WRITE that file, and
        // `putObject(bucket, key, File)` / `upload(...)` READ it. The service rule in Classifier already
        // returns NET, and `classify` returns ONE effect, so the Fs half had nowhere to go and was
        // invisible: a `deny Fs` gate over an S3 archival path saw nothing.
        //
        // THIS IS NOT THE `serde_json::from_reader` CAVEAT, and the difference is why it belongs here. That
        // caveat says: a library moving bytes through a handle the CALLER opened must not be charged,
        // because the caller's `File::open` already carries the Fs. But `new java.io.File(path)` in Java
        // OPENS NOTHING — it is a path wrapper, and candor rightly treats it as pure. So when the SDK
        // writes that file, the Fs happens ONLY inside the SDK, and charging nobody loses it entirely.
        //
        // Co-emitted the way `Llm` co-emits `Net` above: `dir` is a set, so this is additive and the NET
        // the service rule found is never displaced. Gated on the SAME owner shape the Net rule uses plus
        // a File/Path in the DESCRIPTOR, so a pure same-named value type (`AmazonS3URI.getBucket`) cannot
        // match — it takes no File and is not a client.
        if (isS3TransferOwner(owner) && !min.name.equals("<init>")) {
            String p = Classifier.paramsOf(min.desc);
            if (p.contains("Ljava/io/File;") || p.contains("Ljava/nio/file/Path;")) {
                dir.add(Effect.FS);
                if (effect == null) effect = Effect.FS;
            }
        }
        opaqueTaskHandoff(ctx, s, min, owner);
        namedFunctionalToHof(ctx, s, min);
        xmlParseFilePrecision(ctx, s, min);
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
            // `es.submit(new lib.Task())` — the Unknown above is correctly suppressed for a `new T`, since
            // the NEW-site edge attributes T's run()/call(). But that edge is project-only: when T belongs
            // to a chained DEPENDENCY the task body was attributed NOWHERE, and the suppression left the
            // scheduling method silent-pure. The parameter is already gated to Runnable/Callable by
            // TASK_ARG_PREFIXES, so the constructed type is a task type and its reported surface is what
            // the runtime invokes.
            if (task != null && task.newType != null && !ctx.projectClasses.contains(task.newType))
                for (DepFn d : depFnsInvokedByHandoff(task.newType, handoffInvoked(taskArgIface(min.desc))))
                    inheritDepFn(id, d);
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
            Type[] pt = Type.getArgumentTypes(min.desc);
            List<ProvValue> args = callArgs(provFrames[mn.instructions.indexOf(min)], min);
            for (int i = 0; i < args.size(); i++) {
                ProvValue a = args.get(i);
                if (a == null || a.newType == null) continue;
                ctx.edges.get(id).addAll(functionalSamSurface(a.newType));
                // ACROSS THE SCAN BOUNDARY: the same hand-off, but the functional impl belongs to a chained
                // DEPENDENCY. `functionalSamSurface` reads the project ClassNode, so a dep type yields an
                // empty surface — and the opaque-handoff Unknown does not fire either, because the argument
                // HAS a `newType`. The site got neither an edge nor an Unknown: silent-pure
                // (candor-spec SOUNDNESS-VEIN-crossing-the-scan-boundary.md, JVM root cause 2).
                // Gated on the PARAMETER's declared type being a functional interface, so an ordinary object
                // that merely happens to be constructed at a HOF call site (`map.merge(k, new Val(), fn)`)
                // is never charged its whole surface.
                if (i < pt.length && isHofFunctionalIface(pt[i].getInternalName())
                        && !ctx.projectClasses.contains(a.newType))
                    for (DepFn d : depFnsInvokedByHandoff(a.newType, handoffInvoked(pt[i].getInternalName())))
                        inheritDepFn(id, d);
            }
        }
    }

    /** XML parse(File) precision: the File overload definitely reads the file — add Fs beside the
     *  XXE Unknown classify() already yields. */
    static void xmlParseFilePrecision(AnalysisContext ctx, MethodScan s, MethodInsnNode min) {
        EffectSet dir = s.dir;
        // XML parse(File) PRECISION: the parser's `parse` already classifies as the XXE/external-
        // entity Unknown (security disclosure, see classify ~4367). The File overload ALSO
        // DEFINITELY reads the file — add Fs here so the effect set is the precise {Fs, Unknown}
        // (reads this file for sure; may resolve external entities). The InputStream/InputSource
        // overloads (caller stream) and the (String systemId) overload (path-vs-URL ambiguous)
        // get no Fs. Added in the call handler because classify()'s single slot is the Unknown.
        if ((min.owner.equals("javax/xml/parsers/DocumentBuilder")
                || min.owner.equals("javax/xml/parsers/SAXParser"))
                && min.name.equals("parse") && min.desc.startsWith("(Ljava/io/File;")) {
            dir.add(Effect.FS);
            // ⟨0.29⟩ …AND ITS DIRECTION. This branch adds `Fs` OUTSIDE `effectMetadata`, the single place
            // that refines a classified effect, so `fs` came back ABSENT here — and absent is not neutral.
            // `effectMetadata`'s own comment states the harm: "Recording nothing let a caller of this
            // function inherit a neighbour's ["write"] and thereby claim 'writes but never reads' over a
            // reach whose kind was never determined — the partial claim §2 forbids", and it names the
            // fixture PART 31 caught it with: `mixed()`, one writer plus one undetermined-kind callee.
            //
            // MEASURED, the same fixture and the same wrong answer, reintroduced through this branch:
            //     parseFile  fs=None        generalWrite fs=["write"]
            //     mixed (calls both)  ->  fs=["write"]      ← "writes but never reads", falsely
            //
            // `read`, not the FS_UNKNOWN poison, because the comment above already proves the direction:
            // the File overload "reads this file for sure". That is strictly better than abstaining and
            // is decided by the same condition that selected the branch.
            ctx.fsDirect.computeIfAbsent(s.id, x -> new java.util.TreeSet<>()).add("read");
        }
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
                    for (ProvValue a : callArgs(rf, min)) reentryEdgeOrDisclose(id, a, C_TOSTRING);
                }
            }
            if (isEqualsHashSink(min.owner, min.name)) {
                // The KEY/element argument — for Map.* it is the FIRST arg (the key); for the
                // collection verbs it is the lone element arg. Reenter both equals AND hashCode.
                ProvValue key = callArg(rf, min, 0);
                reentryEdgeOrDisclose(id, key, C_EQUALS);
                reentryEdgeOrDisclose(id, key, C_HASHCODE);
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
                reentryEdge(id, elem, C_COMPARETO, comparesArgZero(min.owner, min.name));
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
        // values() clone) are types, not packages, and stay out. A package outside the
        // curated coverage list is a named blind spot at every call shape κ floors.
        if (!ctx.projectClasses.contains(min.owner) && min.owner.charAt(0) != '[') {
            int slash = min.owner.lastIndexOf('/');
            // AN UNFORMABLE KEY IS DISCLOSED UNDER A STAND-IN, NEVER DROPPED. A class in the DEFAULT
            // package has no slash, so this yielded "" and the `!pkg.isEmpty()` guard below skipped the
            // ledger AND `blindDirect` — a floored call into an external default-package class was
            // silently invisible, with no uncovered entry and no blind propagation to its callers. Every
            // package-qualified owner discloses at a single call; only the one whose key could not be
            // formed vanished, which is the shape the family's could-not-form-a-key rule exists for.
            // The stand-in avoids `<>`: the serializer HTML-escapes them, and the ledger key reached the report
            // as "\u003cdefault\u003e". A real Java package cannot contain parentheses or a space, so this
            // cannot collide with one and needs no escaping.
            String pkg = slash > 0 ? min.owner.substring(0, slash).replace('/', '.') : "(default package)";
            if (!pkg.isEmpty() && !kappaCovers(pkg)) {
                // A FLOORED call (classifier returned pure) into an uncurated external package is a
                // per-method blind spot, propagated to callers. A call κ actually CLASSIFIED is not — its
                // effect is on the record — so it is counted in NEITHER the ledger nor the call tally, and
                // a package whose every call is classified never enters the ledger at all. Note the
                // asymmetry: a classification vouches for the CALL it fired on, never for the package,
                // which is why kappaUncovered() no longer consults a package-wide "was ever classified"
                // set. The tally must mean the same thing as the name beside it: calls whose effects this
                // scan could not see.
                if (effect == null) {
                    ctx.kappaSeen.merge(pkg, 1, Integer::sum);
                    ctx.blindDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(pkg);
                }
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
            // A verb that reveals no direction must POISON the fixpoint, not merely abstain. Recording
            // nothing let a caller of this function inherit a neighbour's ["write"] and thereby claim
            // "writes but never reads" over a reach whose kind was never determined — the partial claim §2
            // forbids. FS_UNKNOWN was injected only for CROSS-JAR Fs (`viaCross`); a LOCAL call whose verb
            // is mode-dependent (`new RandomAccessFile(path, "rw")`, `open`) is exactly the same
            // situation and was silently absent from the guard.
            //
            // Found by conformance PART 31 on its first run: `mixed()`, calling one writer and one
            // undetermined-kind callee, reported fs=["write"].
            ctx.fsDirect.computeIfAbsent(id, x -> new TreeSet<>()).addAll(k.isEmpty() ? List.of(FS_UNKNOWN) : k);
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
            boolean urlTerminalCapturedHost = false;
            if (urlTerminal) {
                String h = urlTerminalHost(min, urlLocals, constLocals);
                if (h != null) {
                    urlTerminalCapturedHost = true;
                    ctx.hostsDirect.computeIfAbsent(id, x -> new TreeSet<>()).add(h);
                    dir.addAll(EffectSet.ofNames(modelHostEffects(h))); // §1 ⟨0.13⟩ Llm host-literal refinement
                } else ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Net");
            }
            if (hostLessOwner || runtimeStringHost)
                ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Net");
            // THE GENERAL RULE, and the two above are special cases of it: a Net call that contributes NO
            // VISIBLE HOST leaves this function's host surface incomplete. Stating it per-idiom missed the
            // shapes where the owner IS host-bearing but the invoked overload carries no host —
            // `HttpClient.send(request, handler)`, `Socket.connect(SocketAddress)`, `DatagramSocket.send`,
            // a field-held `URLConnection`. Alone those were still `unknown-host` (via the empty-hosts
            // branch, which is per FUNCTION), but combined with any literal sibling in the same method the
            // branch stopped firing and a benign literal CERTIFIED the invisible endpoint:
            //
            //     new URL("https://sentry.io/x").openStream();      // literal
            //     client.send(request, handler);                    // runtime-computed
            //     -> netClass ["known-telemetry"]     an `allow Net known-telemetry` policy PASSED it
            //
            // Net destination-class is fail-closed by design (SPEC §6.2). Deriving the marker from what the
            // call actually yielded, rather than from a list of idioms, is what makes it fail closed for
            // the idioms nobody enumerated.
            // Restricted to calls that TAKE ARGUMENTS. A zero-argument Net call — `socket.close()`,
            // `conn.disconnect()`, `stream.flush()` — cannot carry a destination, so it is evidence of
            // neither completeness nor incompleteness; excluding it is not narrowing past a reach, it is
            // declining to read a non-signal. Without this the rule fired on the `.close()` in
            // `new Socket("api.x.com", 443).close()` and flagged a method whose host is fully visible —
            // caught by an existing masking test, which is the argument for running the whole suite.
            boolean carriesArgs = !min.desc.startsWith("()");
            if (carriesArgs && !capturedHostHere && !urlTerminalCapturedHost)
                ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Net");
        }
        // Table literals from THIS SQL-bearing call's OWN argument (the executed/prepared SQL) —
        // same per-call attribution. tablesInSql needs a leading SQL keyword so a non-SQL arg
        // yields nothing; a SQL-shaped log line in another statement is no longer mis-attributed.
        // ⟨0.29⟩ …but NOT from a PARAMETER BINDER. `PreparedStatement.setString(1, v)` and its siblings
        // take a VALUE, never a query, and they sit on a SQL-bearing owner with a `String` in the
        // descriptor — so the window read them and any value that happens to parse as SQL became a table.
        // MEASURED: `p.setString(1, "SELECT * FROM audit_log")` on a statement whose SQL is a RUNTIME
        // value published `tables: ["audit_log"]` — a table this query may never touch. The verdict stayed
        // safe because the `prepareStatement(runtimeSql)` call marks `incomplete` on its own, so this is a
        // fabricated SURFACE rather than a certification (candor-ts had the same shape WITHOUT the hedge,
        // and there it certified); a report that names the wrong table is still a report nobody can act on.
        //
        // The same carve-out shape as `FS_USE_VERBS`/`EXEC_USE_VERBS`: a method on a bearing owner whose
        // argument is data. Forgetting a binder here fabricates; wrongly listing a query-bearing method
        // would UNDER-report — so the set is the JDBC binder prefix, which is closed and named by the API.
        if (isSqlBearingOwner(min.owner) && min.desc.contains("Ljava/lang/String;")
                && !isSqlParameterBinder(min.name)) {
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
            String monoRecv = null;
            if (inh == null && (xop == Opcodes.INVOKEVIRTUAL || xop == Opcodes.INVOKEINTERFACE)) {
                String cRecv = monomorphicReceiver(provFrames == null ? null
                        : provFrames[mn.instructions.indexOf(min)], min);
                monoRecv = cRecv;
                if (cRecv != null && !ctx.byName.containsKey(cRecv) && !cRecv.equals(min.owner))
                    inh = ctx.crossDeps.get(cRecv + "." + min.name + min.desc);
            }
            // Still nothing under any key we could form — the two readings of that emptiness are not
            // the same claim. Disclose the one that licenses nothing (see untypedDepReceiver).
            if (inh == null) untypedDepReceiver(ctx, s, min, xop, monoRecv);
            if (inh != null) {
                // ONE place applies a DepFn. This block used to duplicate `inheritDepFn` line for line,
                // and the two had already drifted: the ⟨0.19⟩ reason class was taught to one and not the
                // other, so a reason-scoped gate worked at the task/HOF hand-off sites and was inert on the
                // ORDINARY call — the overwhelmingly common path. Duplicated propagation logic is how a
                // rung ends up shipped-but-inert in half the places it matters.
                inheritDepFn(id, inh);
            }
        }
        // INHERITED / DEFAULT METHOD FROM A DEPENDENCY SUPERTYPE. The join above requires a NON-project
        // owner, and that is exactly why this shape escaped it: `this.load()` on a project class extending
        // a dependency's `Base` compiles to INVOKEVIRTUAL with the PROJECT class as owner, so the join was
        // never even reached. The local resolution misses it too — `nearestConcreteSuper` walks
        // project-only indexes, so a dependency supertype yields nothing, and an empty CHA emits no Unknown
        // either. The consumer of an effectful inherited/default method therefore read silent-pure, with
        // the dependency's report carrying the body under `lib/Base.load()V` all along
        // (candor-spec SOUNDNESS-VEIN-crossing-the-scan-boundary.md, JVM root cause 1).
        //
        // `nearestDepFn` walks the project class's OWN supertype chain — visible here precisely because the
        // subclass is in this scan and its ClassNode names its dependency parent — and stops at the first
        // declaration, so a project override (concrete or abstract) shadows the dependency body and nothing
        // is charged. With no chained report it short-circuits and the scan is unchanged.
        if (effect == null && !springTyped && ctx.projectClasses.contains(min.owner)) {
            DepFn inherited = nearestDepFn(min.owner, min.name, min.desc);
            // A dep entry whose ENTIRE content is Unknown carries no positive effect — it is the
            // dependency saying "I could not resolve this dispatch", which is what its own scan reports for
            // an ABSTRACT declaration with no implementor inside it. When THIS scan resolves the same
            // signature (the project CHA is non-empty), importing that Unknown replaces a complete local
            // answer with an unresolved one: on jackson-databind chained onto jackson-core, the single
            // abstract `ResolvedType.isReferenceType()` turned 12 fully-resolved functions Unknown, every
            // one of them resolvable — and resolved — from the databind subtypes in the scan. Trading a
            // silent under-report for manufactured uncertainty is the same bad bargain as fabricating an
            // effect. A dep entry with REAL effects is still inherited, resolved locally or not, because
            // that is positive information this scan does not otherwise have.
            if (inherited != null && inherited.effects.size() == 1
                    && inherited.effects.contains(Effect.UNKNOWN)
                    && !chaTargets(min.owner, min.name, min.desc).isEmpty())
                inherited = null;
            inheritDepFn(id, inherited);
        }
    }

    /**
     * THE UNTYPED CROSS-PACKAGE RECEIVER — half 1 of candor-spec {@code DEP-RECEIVER-TYPING-DESIGN.md}:
     * DISCLOSE the key that was never formed.
     *
     * <p>A chained lookup that comes back empty has two readings with opposite evidential weight.
     * KEYED-AND-MISSED — the engine formed the hash and the dep's report has no entry — IS a purity
     * claim, because a dep report omits its pure functions (SPEC §2 rule 3), and silence is the right
     * answer. COULD-NOT-FORM-A-KEY — the dispatch target was never named, so no lookup happened — is
     * not an answer to anything, and dropping it makes the CALLER a confident purity claim: absent from
     * {@code functions} while counted in ⟨0.21⟩ {@code analyzed}. That is the cardinal sin, and on the
     * JVM it is the queue's open "dep-interface-typed dispatch to a dep impl" (candor-spec
     * SOUNDNESS-VEIN-crossing-the-scan-boundary.md): {@code Store s = Factory.build(); s.save()}
     * compiles to INVOKEINTERFACE on {@code lib/Store}, the body is keyed {@code lib/FileStore.save},
     * the CHA over PROJECT classes is empty — and an empty CHA emits no Unknown, only a dropped edge.
     *
     * <p>The trigger is a CONJUNCTION, not "unresolved receiver". Measured over nine chained JVM
     * corpora, "unresolved receiver into a chained dep" alone fires on 5.4% of all analyzed functions
     * (8.4% on logback-classic) — the false-uncertainty flood candor-spec COVERAGE-GRANULARITY-FINDING
     * .md puts at 8–25%. Five conjuncts cut that to 0.49%:
     *
     * <ol>
     *   <li><b>INVOKEINTERFACE.</b> The bytecode PROVES the static owner is an interface, so the hash
     *       we formed names a declaration, not the body the JVM runs. INVOKEVIRTUAL is excluded: a
     *       plain dep class usually IS the body, so its absence from the report is a real purity
     *       claim. (An abstract dep CLASS is therefore a residual — half 2's {@code typeSurface}.)
     *   <li><b>The receiver is not provably typed.</b> A monomorphic {@code new T} receiver has already
     *       been re-keyed on T above; if THAT missed, the key was exact and the miss is real.
     *   <li><b>The dependency is CHAINED</b> — the owner's package is in {@code depChainedPkgs}. For an
     *       UNCHAINED package the κ ledger already discloses {@code invisible: [pkg]}, so a second
     *       disclosure is pure false uncertainty; it is precisely when the dep IS chained that the
     *       ledger correctly falls silent (§2 rule 3) and the silence becomes the confident claim.
     *       The rust engine found this conjunct the same way — by measuring.
     *       <p>This reads {@code depChainedPkgs}, NOT the §2.1-trust-gated {@code depCoveredPkgs}, and
     *       the difference is measured rather than argued. Chained-ness is a fact about the
     *       CONFIGURATION and no version check unsettles it; coverage is an authority for silence and a
     *       stale report has none. Routing this conjunct through the trust-gated set turned
     *       logback-classic's {@code ContextInitializer.printConfiguratorOrder} from {@code ['Unknown']}
     *       to {@code []} — a disclosed dispatch reduced to an empty purity claim, with no {@code
     *       invisible} to take its place because {@code ch.qos.logback} is a κ-CURATED-covered prefix.
     *   <li><b>No project impl.</b> A non-empty CHA means the dispatch HAS a local answer; whether that
     *       answer is complete is the documented bounded-CHA trade, not this rung.
     *   <li><b>The dep demonstrably holds an effectful body with this exact signature</b>, under some
     *       other owner. Without it the disclosure lands overwhelmingly on interfaces whose every
     *       implementation in the dep is a pure accessor ({@code Header.getValue}, {@code
     *       HttpRequest.getMethod}) — 2.1% of functions hedged to say nothing.
     * </ol>
     *
     * <p>Conjunct 5 is a signature join, and a signature join is exactly what
     * DEP-RECEIVER-TYPING-DESIGN rejects for RESOLUTION ("leaves as generic as write, run or send would
     * fabricate on unrelated receivers"). It is used here only as EVIDENCE TO DISCLOSE — nothing is
     * charged, no edge is formed, no effect is inherited — which is the behaviour that document
     * prescribes when the type surface is absent: "the correct behaviour is half 1 — disclose — not a
     * widened match." A collision costs one conservative Unknown on a site candor genuinely cannot
     * resolve; it can never fabricate an effect.
     */
    static void untypedDepReceiver(AnalysisContext ctx, MethodScan s, MethodInsnNode min,
            int xop, String monoRecv) {
        if (xop != Opcodes.INVOKEINTERFACE) return;                        // conjunct 1
        if (monoRecv != null) return;                                      // conjunct 2
        if (isChaExemptMethod(min.owner, min.name, min.desc)) return;      // the conventionally-pure surface
        int slash = min.owner.lastIndexOf('/');
        if (slash <= 0) return;
        if (!ctx.depChainedPkgs.contains(min.owner.substring(0, slash).replace('/', '.'))) return; // conjunct 3
        if (!chaTargets(min.owner, min.name, min.desc).isEmpty()) return;  // conjunct 4
        if (!depDeclaresSigElsewhere(ctx, min)) return;                    // conjunct 5
        s.dir.add(Effect.UNKNOWN);
        ctx.unknownWhy.computeIfAbsent(s.id, k -> new TreeSet<>()).add(UnknownReason.of(
                UnknownReason.Kind.DISPATCH, min.owner.replace('/', '.') + "." + min.name));
    }

    /** Does a chained dep report hold an EFFECTFUL body with this exact {@code name+desc} under a
     *  DIFFERENT owner? Evidence that the interface this site dispatches on has a reachable effectful
     *  implementation whose key this scan cannot name. Inverts {@code crossDeps} once, lazily.
     *
     *  <p><b>A LATCH OVER AN EMPTY INPUT IS PERMANENT, and nothing here would ever rebuild it.</b>
     *  {@code depOwnersBySigBuilt} is set unconditionally once this is entered, so an entry BEFORE
     *  {@code loadCrossDeps} has populated {@code crossDeps} would freeze the empty inversion for the
     *  whole scan — every later site answering "no, the dep declares nothing" and the disclosure it gates
     *  falling silent. That cannot happen today: the sole caller is {@link #untypedDepReceiver}'s conjunct
     *  5, reached only past conjunct 3's {@code depChainedPkgs} test, and that set is written only by
     *  {@code loadCrossDeps}. But nothing in THIS method prevents it, which is the difference between
     *  absent and absent-by-accident — and its two siblings {@link #depFnsOfType}/{@link #depFnsNamed}
     *  already guard exactly this way, so the inconsistency was the tell. Returning without latching is
     *  behaviourally identical today (an empty inversion yields a null lookup, hence false) and leaves
     *  the memo rebuildable if a future ordering ever does reach it early. */
    static boolean depDeclaresSigElsewhere(AnalysisContext ctx, MethodInsnNode min) {
        if (ctx.crossDeps.isEmpty()) return false;
        if (!ctx.depOwnersBySigBuilt) {
            for (String h : ctx.crossDeps.keySet()) {
                int paren = h.indexOf('(');
                int dot = paren < 0 ? -1 : h.lastIndexOf('.', paren);
                if (dot > 0) ctx.depOwnersBySig
                        .computeIfAbsent(h.substring(dot + 1), k -> new HashSet<>()).add(h.substring(0, dot));
            }
            ctx.depOwnersBySigBuilt = true;
        }
        Set<String> owners = ctx.depOwnersBySig.get(min.name + min.desc);
        if (owners == null) return false;
        for (String o : owners) if (!o.equals(min.owner)) return true;
        return false;
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
                    // ACROSS THE SCAN BOUNDARY. `Classifier` knows the JDK and the frameworks; it knows
                    // nothing about the user's OWN dependency, so `xs.forEach(DepUtil::write)` and
                    // `xs.forEach(d::writeInst)` fell through it and read silent-pure — while the direct
                    // call `DepUtil.write(x)` inherits correctly through the cross-jar join. The reference
                    // form got neither an edge nor an Unknown, because the opaque-handoff fallback is
                    // suppressed for anything `fromIndy` (candor-spec
                    // SOUNDNESS-VEIN-crossing-the-scan-boundary.md, JVM root cause 2).
                    //
                    // A method handle carries the EXACT owner, name and descriptor, so this is the same
                    // precise hash the direct call joins on — no resolution guessing. `deferred` gates it
                    // exactly as it gates the project edge: a reference merely stowed for later must not be
                    // attributed here. Also the class-load trigger, as for a project static/ctor ref.
                    if (!deferred) inheritDepFn(id, ctx.crossDeps.get(h.getOwner() + "." + h.getName() + h.getDesc()));
                    inheritDepClinit(id, h.getOwner());
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

    /** Inherit a DEPENDENCY class's `<clinit>` effects from a chained report (see {@link #clinitEdge}). */
    static boolean inheritDepClinit(String callerId, String internalOwner) {
        AnalysisContext c = ctx();
        if (c.projectClasses.contains(internalOwner)) return true;   // a project class edges locally instead
        DepFn d = c.crossDeps.get(internalOwner + ".<clinit>()V");
        inheritDepFn(callerId, d);
        return d != null;
    }

    /** Fold a chained dependency unit's effects + literal surfaces into `callerId`. The cross-jar
     *  join (§2) does this for a direct CALL into the dep; every other route that provably reaches a dep
     *  body — an implicit contract reentry, a `<clinit>` trigger, an inherited method — needs the same
     *  fold, because the dep's unit lives in another report and cannot be edged to as a node.
     *  A null `d` (no chained report covers that hash) is a no-op, exactly as before the lookup existed. */
    static void inheritDepFn(String callerId, DepFn d) {
        if (d == null) return;
        AnalysisContext c = ctx();
        c.viaCross.computeIfAbsent(callerId, k -> EffectSet.empty()).addAll(d.effects);
        if (!d.hosts.isEmpty()) c.hostsDirect.computeIfAbsent(callerId, k -> new TreeSet<>()).addAll(d.hosts);
        if (!d.cmds.isEmpty()) c.cmdsDirect.computeIfAbsent(callerId, k -> new TreeSet<>()).addAll(d.cmds);
        if (!d.paths.isEmpty()) c.pathsDirect.computeIfAbsent(callerId, k -> new TreeSet<>()).addAll(d.paths);
        if (!d.tables.isEmpty()) c.tablesDirect.computeIfAbsent(callerId, k -> new TreeSet<>()).addAll(d.tables);
        if (d.netClass.contains("unknown-host"))
            c.surfaceIncomplete.computeIfAbsent(callerId, k -> new TreeSet<>()).add("Net");
        // ⟨0.29⟩ …AND EVERY OTHER EFFECT THE DEPENDENCY COULD NOT LOCATE. `Net` has had its wire form
        // since ⟨0.20⟩ (`netClass ∋ unknown-host`, the line above); `Fs`/`Exec`/`Db` had none, so the
        // join copied a dependency's paths and dropped its "I could not see where". Measured: a consumer
        // writing ONE allowed literal beside a call into a dep whose path is a runtime value certified
        // clean under `allow Fs <literal>`, where candor-rust — which has published `incomplete` all
        // along — charges AS-EFF-008 on the same shape.
        for (String eff : d.incomplete)
            c.surfaceIncomplete.computeIfAbsent(callerId, k -> new TreeSet<>()).add(eff);
        // The REASON CLASS travels with the Unknown. §2's transitive rule already carries the effect; the
        // class has to ride with it or a reason-scoped gate silently degrades to "some Unknown, cause
        // unknown" exactly at the boundary. Only meaningful when the dep actually contributed an Unknown —
        // a dep with reasons but no Unknown effect cannot make this caller reason-scoped.
        if (d.effects.hasUnknown()) {
            for (String tag : depTransitiveWhy(d)) {
                UnknownReason r = UnknownReason.parse(tag);
                if (r != null) c.unknownWhy.computeIfAbsent(callerId, k -> new TreeSet<>()).add(r);
            }
        }
    }

    /** Every reason tag the dependency unit {@code d} reaches — its own, PLUS those of everything it calls,
     *  transitively, through the {@code calls} graph its own report published.
     *
     *  <p><b>Why the direct tags are not enough, measured.</b> {@code unknownWhy} is DIRECT by contract —
     *  "why Unknown was emitted HERE, not inherited" — because its other consumers ({@code candor
     *  blindspots}, the `Unknown sources (direct)` summary) want SOURCES. So a dep unit whose Unknown was
     *  inherited from a callee publishes {@code inferred: ['Unknown']} and NO {@code unknownWhy} at all,
     *  and the ⟨0.19⟩ boundary fix ({@code 6ab26e4}) — which carries {@code d.unknownWhy} across — finds
     *  nothing to carry. One hop further than that fix looked, the class dies:
     *  <pre>
     *    lib.Deep.go      ['Unknown']  unknownWhy ['reflect:java.lang.Class.forName', …]
     *    lib.Shallow.call ['Unknown']  unknownWhy ABSENT            calls ['lib.Deep.go']
     *
     *    deny Net Unknown[reflect] app     both trees in one scan          exit 1
     *                                      app chaining lib's report       exit 0   <- fail-OPEN
     *                                      (bare `deny Net Unknown`        exit 1  — the Unknown IS there,
     *                                       only its CLASS was missing)
     *  </pre>
     *
     *  <p><b>No format rung: the dependency's report already held the answer under the right key.</b>
     *  {@code calls} (SPEC §2) is the dep's effect-relevant local call graph, and it is exactly the edge
     *  set an Unknown propagates along — a callee with no effects cannot have contributed one, and is
     *  omitted from {@code calls} for the same reason. So the closure over {@code calls} from a unit that
     *  carries Unknown is precisely the set of units whose reasons that Unknown could have come from.
     *
     *  <p><b>It cannot over-attribute.</b> Applied only when the joined unit itself carries Unknown, and
     *  every tag it returns belongs to a unit this caller demonstrably reaches through it — the same
     *  transitive rule §2 already uses for the EFFECT. A report that omits {@code fn} or {@code calls}
     *  (an older or foreign producer) simply yields the direct tags, i.e. today's behaviour, never less.
     *  Memoised per qual; {@code seen} bounds a cyclic call graph. */
    static List<String> depTransitiveWhy(DepFn d) {
        if (d.fn == null) return d.unknownWhy;              // no qual → no handle on `calls` → direct only
        AnalysisContext c = ctx();
        List<String> memo = c.depTransWhyMemo.get(d.fn);
        if (memo != null) return memo;
        TreeSet<String> out = new TreeSet<>(d.unknownWhy);
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> q = new ArrayDeque<>(c.depCallsByFn.getOrDefault(d.fn, List.of()));
        seen.add(d.fn);
        while (!q.isEmpty()) {
            String n = q.poll();
            if (!seen.add(n)) continue;
            out.addAll(c.depWhyByFn.getOrDefault(n, List.of()));
            q.addAll(c.depCallsByFn.getOrDefault(n, List.of()));
        }
        List<String> result = List.copyOf(out);
        c.depTransWhyMemo.put(d.fn, result);
        return result;
    }

    /** The chained-dependency record for the `(name,desc)` body a value of static type `internal` would
     *  actually invoke — the cross-boundary analogue of {@link Cha#nearestConcreteSuper}.
     *
     *  <p>Walks `internal` and its supertypes NEAREST-FIRST and stops at the first declaration it finds.
     *  If that declaration is a PROJECT one, returns null: a concrete project body is analyzed in this
     *  scan and edged to normally, and an ABSTRACT project declaration OVERRIDES any dependency default
     *  further up (every concrete subtype must then supply its own body, which CHA already enumerates).
     *  Either way, charging the dependency's shadowed implementation on top would FABRICATE an effect the
     *  JVM never runs — worse than the miss it fixes. Only when the nearest declaration is a dependency's,
     *  and a chained report carries it, is there anything to inherit.
     *
     *  <p>NEAREST-FIRST is {@link Cha#resolutionOrder}'s definition of nearest — the superclass chain
     *  before any interface — not "by depth". A depth-ordered walk let a nearer interface {@code default}
     *  answer for a descriptor a superclass body owns, which the JVM never does. */
    static DepFn nearestDepFn(String internal, String name, String desc) {
        if (internal == null) return null;
        AnalysisContext c = ctx();
        if (c.crossDeps.isEmpty()) return null;                 // no chained report — nothing to look up
        for (String t : Cha.resolutionOrder(internal, true)) {
            ClassNode cn = c.byName.get(t);
            if (cn != null && declaresMethod(cn, name, desc)) return null;   // a project declaration wins
            DepFn d = c.crossDeps.get(t + "." + name + desc);
            if (d != null) return d;
        }
        return null;
    }

    /** EVERY chained-dependency unit declared by `internalOwner`, whatever the descriptor. Used where the
     *  route into the dependency is a HAND-OFF rather than a call: a `new lib.Consumer()` passed to a
     *  forEach/executor is invoked through its SAM, and the descriptor at the hand-off site is the ERASED
     *  functional-interface one (`accept(Object)`) while the report keys the real specialized body
     *  (`accept(String)`), so there is no single hash to join on. Taking the type's whole reported surface
     *  mirrors {@link #functionalSamSurface}, which edges every method of a project functional impl for the
     *  same reason — such a type exists to be invoked, and its surface is one or two methods. */
    /** The SAM method names of every functional interface `TASK_ARG_PREFIXES` / `isHofFunctionalIface`
     *  admit, plus `<init>`. A hand-off invokes exactly ONE member of the constructed type — the
     *  interface's single abstract method — and the constructor, which runs at the `new` site itself.
     *  Every other member of that type is unreachable through the hand-off.
     *
     *  Without this filter `depFnsOfType` returned the type's WHOLE reported surface: an
     *  `executor.submit(new lib.ReportJob())` inherited `exportCsv()`'s Fs and `upload()`'s Net —
     *  public helpers the executor never calls — onto the scheduling method, failing a `deny Net` on a
     *  service that only enqueues work. The comment at the call site argued the parameter gate made the
     *  surface safe; the gate constrains which TYPE is handed off, never which MEMBER runs. */
    /** Functional interface -> its single abstract method. Keyed by INTERFACE, not by method name, because
     *  the interface set is CLOSED (isFunctionalIface / isHofFunctionalIface / TASK_ARG_PREFIXES all gate on
     *  an explicit list) while the set of SAM names is not. An earlier version allowlisted the NAMES and
     *  promptly omitted `getAsInt`/`getAsLong`/`getAsDouble`/`getAsBoolean`, which would have silently
     *  dropped an `IntSupplier` implementation's effects — an allowlist under-reports exactly what you
     *  forgot, which is why this project prefers a denylist over a sound over-approximation.
     *
     *  A `java/util/function/` interface not listed here falls through to the CONSERVATIVE branch below
     *  (charge the whole surface) rather than to silence: over-charging is loud in an A/B and is the
     *  fabrication side, whereas a missed SAM is the cardinal sin and is invisible. */
    static final Map<String, String> SAM_OF = Map.ofEntries(
            Map.entry("java/lang/Runnable", "run"),
            Map.entry("java/util/TimerTask", "run"),
            Map.entry("java/security/PrivilegedAction", "run"),
            Map.entry("java/security/PrivilegedExceptionAction", "run"),
            Map.entry("java/util/concurrent/Callable", "call"),
            Map.entry("java/util/Comparator", "compare"),
            Map.entry("java/io/FileFilter", "accept"),
            Map.entry("java/io/FilenameFilter", "accept"),
            Map.entry("org/apache/commons/io/function/IOConsumer", "accept"),
            Map.entry("java/util/function/Function", "apply"),
            Map.entry("java/util/function/BiFunction", "apply"),
            Map.entry("java/util/function/UnaryOperator", "apply"),
            Map.entry("java/util/function/BinaryOperator", "apply"),
            Map.entry("java/util/function/Consumer", "accept"),
            Map.entry("java/util/function/BiConsumer", "accept"),
            Map.entry("java/util/function/Supplier", "get"),
            Map.entry("java/util/function/Predicate", "test"),
            Map.entry("java/util/function/BiPredicate", "test"));

    /** The members a hand-off through {@code iface} can actually invoke: that interface's SAM, plus
     *  {@code <init>} — the constructor runs at the {@code new} site itself, so its effects ARE reached.
     *  An UNKNOWN interface yields null, and the caller then falls back to the whole surface. */
    /** The functional interface an executor-style hand-off declares as its FIRST parameter, from the
     *  callee's descriptor — the same descriptors `TASK_ARG_PREFIXES` gates on, read back so the SAM is
     *  derived rather than guessed. Null when the shape is not one we model, which fails SAFE. */
    static String taskArgIface(String desc) {
        if (desc == null) return null;
        for (String p : Rules.TASK_ARG_PREFIXES) {
            if (desc.startsWith(p)) return p.substring(2, p.length() - 1);   // "(Lfoo/Bar;" -> "foo/Bar"
        }
        return null;
    }

    static Set<String> handoffInvoked(String iface) {
        String sam = iface == null ? null : SAM_OF.get(iface);
        return sam == null ? null : Set.of("<init>", sam);
    }
    // RESIDUAL, measured and left: the filter matches the SAM by NAME, not by descriptor, so a type
    // implementing two interfaces whose SAMs share a name (`Consumer.accept(Object)` and
    // `IntConsumer.accept(int)`) contributes both overloads. Narrowing further needs the SAM's erased
    // descriptor. This over-charges, which is the safe direction and far narrower than the whole-surface
    // behaviour it replaced — a `Sink` implementing both now yields {Fs, Net} instead of {Fs, Net, Env}.

    /** Like {@link #depFnsOfType}, restricted to the members a hand-off can actually invoke. */
    static List<DepFn> depFnsInvokedByHandoff(String internalOwner, Set<String> allowed) {
        AnalysisContext c = ctx();
        if (c.crossDeps.isEmpty() || internalOwner == null) return List.of();
        // A hand-off through an interface we do not model falls back to the WHOLE surface: an over-charge
        // is visible in an A/B, a dropped SAM is not.
        if (allowed == null) return depFnsOfType(internalOwner);
        List<DepFn> out = new ArrayList<>();
        String prefix = internalOwner + ".";
        for (Map.Entry<String, DepFn> e : c.crossDeps.entrySet()) {
            String h = e.getKey();
            if (!h.startsWith(prefix)) continue;
            int paren = h.indexOf('(', prefix.length());
            if (paren < 0) continue;
            String name = h.substring(prefix.length(), paren);
            if (name.indexOf('/') >= 0) continue;   // a nested owner, not a member of this type
            if (!allowed.contains(name)) continue;
            out.add(e.getValue());
        }
        return out;
    }

    static List<DepFn> depFnsOfType(String internalOwner) {
        AnalysisContext c = ctx();
        if (c.crossDeps.isEmpty() || internalOwner == null) return List.of();
        List<DepFn> memo = c.depFnsByOwner.get(internalOwner);
        if (memo != null) return memo;
        List<DepFn> out = new ArrayList<>();
        String prefix = internalOwner + ".";
        for (Map.Entry<String, DepFn> e : c.crossDeps.entrySet()) {
            String h = e.getKey();
            // `owner.name(desc)` — require the '.' to be followed by a name then '(' with no further '/',
            // so `lib/A.m()V` matches `lib/A` and never `lib/A$Inner` or `lib/Ax`.
            if (!h.startsWith(prefix)) continue;
            int paren = h.indexOf('(', prefix.length());
            if (paren < 0 || h.lastIndexOf('/', paren) >= prefix.length()) continue;
            out.add(e.getValue());
        }
        c.depFnsByOwner.put(internalOwner, out);
        return out;
    }

    /** Every chained-dependency unit `internalOwner` declares under member name `name`, keyed by DESCRIPTOR.
     *  The by-NAME reentry contracts resolve over any descriptor, so the join enumerates them; the key stays
     *  the exact `owner.name(` prefix, so this is NEVER a bare leaf-name match across arbitrary owners.
     *  Memoized per `owner.name`, mirroring {@link #depFnsOfType}'s cost model. */
    static Map<String, DepFn> depFnsNamed(String internalOwner, String name) {
        AnalysisContext c = ctx();
        if (c.crossDeps.isEmpty() || internalOwner == null) return Map.of();
        String key = internalOwner + "." + name;
        Map<String, DepFn> memo = c.depFnsByOwnerName.get(key);
        if (memo != null) return memo;
        Map<String, DepFn> out = new LinkedHashMap<>();
        String prefix = key + "(";       // `owner.name(desc)ret` — the '(' pins the member name exactly
        for (Map.Entry<String, DepFn> e : c.crossDeps.entrySet())
            if (e.getKey().startsWith(prefix)) out.put(e.getKey().substring(key.length()), e.getValue());
        c.depFnsByOwnerName.put(key, out);
        return out;
    }

    /** The chained-dependency records for a by-NAME reentry contract on a value of static type
     *  {@code internal} — the by-NAME analogue of {@link #nearestDepFn}, and the residual that rung left
     *  open. {@code toString}/{@code equals}/{@code hashCode} have ONE descriptor each, so a chained
     *  consumer can compute the exact hash; {@code Comparable.compareTo}, {@code Appendable.append} and
     *  {@code Writer}/{@code Reader}'s {@code write}/{@code read} are re-entered over whichever overload
     *  the JDK sink picks, and that overload is not visible at the consumer's call site — a
     *  {@code TreeSet.add(depItem)} names no descriptor at all. So the join takes the type's WHOLE reported
     *  surface under that name, exactly as the in-scan {@link #reentryTargets} edges every same-named
     *  concrete method of a project subtype.
     *
     *  <p>Three things keep that from becoming the leaf-name join this vein has twice been burned by:
     *  <ul>
     *  <li>the OWNER is pinned to the argument's declared type, which the consumer's own bytecode states —
     *      never "any dependency declaring a method called {@code write}";
     *  <li>the descriptor must match the JDK contract's SHAPE ({@link #contractShapeOk}), so a coincidental
     *      {@code compareTo(String,int)} or {@code void append(..)} helper on the same type is not charged;
     *  <li>per-OVERLOAD shadowing: a project declaration of `name+desc` wins for THAT descriptor only, so
     *      overriding {@code append(char)} neither charges the shadowed body nor drops the inherited
     *      {@code append(CharSequence)}. Whole-name shadowing would have been an under-report, and no
     *      shadowing at all a fabrication.
     *  </ul>
     *  Nearest declaration wins per descriptor, so a dependency subclass's override beats its super's —
     *  where NEAREST is {@link Cha#resolutionOrder}'s order, the superclass chain before any interface. By
     *  DEPTH, a nearer interface {@code default} settled a descriptor that a superclass body owns and the
     *  superclass was then skipped as already decided: a silent under-report on the body the JVM runs. */
    static List<DepFn> nearestDepFnsNamed(String internal, String contract) {
        if (internal == null) return List.of();
        AnalysisContext c = ctx();
        if (c.crossDeps.isEmpty()) return List.of();
        List<DepFn> out = new ArrayList<>();
        Set<String> settled = new HashSet<>();          // descriptors already decided (project or nearer dep)
        for (String t : Cha.resolutionOrder(internal, true)) {
            ClassNode cn = c.byName.get(t);
            if (cn != null)                              // a PROJECT declaration wins for its own descriptor
                for (MethodNode m : cn.methods) if (m.name.equals(contract)) settled.add(m.desc);
            for (Map.Entry<String, DepFn> e : depFnsNamed(t, contract).entrySet()) {
                if (!contractShapeOk(contract, e.getKey())) continue;
                if (settled.add(e.getKey())) out.add(e.getValue());
            }
        }
        return out;
    }

    /** Whether `desc` has the SHAPE the JDK declares for by-NAME contract `contract`. The name alone does
     *  not identify the contract — a dependency type may declare its own `write`/`append`/`read` helpers —
     *  so the descriptor must still be one the contract could be invoked through:
     *  {@code Comparable.compareTo} takes one reference and returns int; {@code Appendable.append} returns a
     *  reference (an override is covariant on {@code Appendable}); {@code Writer}/{@code OutputStream}'s
     *  {@code write} returns void; {@code Reader}/{@code InputStream}'s {@code read} returns int. Every
     *  genuine override matches by construction — an override's descriptor IS the contract's (modulo a
     *  covariant reference return) — so this can only exclude a same-named non-contract member. */
    static boolean contractShapeOk(String contract, String desc) {
        if (desc == null || desc.indexOf(')') < 0) return false;
        String ret = desc.substring(desc.indexOf(')') + 1);
        switch (contract) {
            case C_COMPARETO: {
                Type[] a = Type.getArgumentTypes(desc);
                return ret.equals("I") && a.length == 1 && a[0].getSort() == Type.OBJECT;
            }
            case C_APPEND: return ret.startsWith("L");
            case C_WRITE: return ret.equals("V");
            case C_READ: return ret.equals("I");
            // A by-NAME contract added later and not listed here is admitted, not dropped. This switch is a
            // DENYLIST of shapes proven not to be the contract; as an allowlist it would silently under-report
            // whatever the next contract is, which is the cardinal sin wearing a guard's clothes.
            default: return true;
        }
    }

    /** Whether a {@code compareTo}-reentry sink's argument 0 IS the compared element. The ORDERING sinks
     *  ({@code Collections.sort(List)}, {@code Arrays.sort(Object[])}, {@code list.sort(cmp)}) take a
     *  CONTAINER (or a comparator); their element type is erased inside the generic and is not the
     *  argument's declared type, so resolving the contract over that type answers a question nobody asked —
     *  a container that happens to implement {@code Comparable} would be charged for an ordering the JVM
     *  performs on its ELEMENTS. Only the sinks that take the element/key directly qualify.
     *
     *  <p>Written as a DENYLIST of the container-typed sinks, NOT as a list of the element-typed ones, and
     *  the two spell the same thing today — {@link #isCompareToSink}'s owners are exactly these four plus
     *  TreeSet/TreeMap. They differ in what happens to the NEXT sink somebody adds. As an allowlist, a new
     *  element-taking sink (`PriorityQueue.add`, `ConcurrentSkipListSet.add`, `Collections.binarySearch`)
     *  would default to SUPPRESSING the dependency join and go silently under-reported — a guard defaulting
     *  to the cardinal sin, which is how the sibling fix in this same vein shipped an allowlist of SAM names
     *  with four already missing. As a denylist a new CONTAINER sink defaults to asking the join, and the
     *  join is near-inert there anyway: the argument's declared type is `List`/`Object[]`, and no dependency
     *  report declares a member on those. */
    static boolean comparesArgZero(String owner, String name) {
        if (name.equals("sort") && (owner.equals("java/util/Collections") || owner.equals("java/util/Arrays")
                || owner.equals("java/util/List") || owner.equals("java/util/ArrayList")
                || owner.equals("java/util/LinkedList"))) return false;
        if (owner.equals("java/util/stream/Stream") && name.equals("sorted")) return false;
        return true;
    }

    /** Whether `c` DECLARES `(name,desc)` at all — abstract included. {@link Cha#declaresConcrete} asks the
     *  narrower "is there a body here"; resolution-shadowing asks this one, because an abstract declaration
     *  still overrides an inherited default and redirects dispatch to the concrete subtypes. */
    static boolean declaresMethod(ClassNode c, String name, String desc) {
        if (c == null) return false;
        for (MethodNode mn : c.methods) if (mn.name.equals(name) && mn.desc.equals(desc)) return true;
        return false;
    }

    static void clinitEdge(String callerId, String internalOwner) {
        if (ctx().classesWithClinit.contains(internalOwner))
            ctx().edges.get(callerId).add(internalOwner.replace('/', '.') + ".<clinit>");
        // The owner may be a DEPENDENCY, analyzed separately. Touching it still runs its `<clinit>`, and a
        // chained report records that unit under the ordinary method-ref hash — but nothing looked for it,
        // so a class whose static initializer reads the environment or opens a socket left every consumer
        // reading sound-complete pure. The edge exists for project classes above; this is the same edge on
        // the other side of the scan boundary (candor-spec SOUNDNESS-VEIN-initializer-edge.md, the JVM
        // sibling of candor-ts's module-import edge). Inheritance, not an edge, because the dep's unit lives
        // in another report. Superclasses too: JVMS §5.5 initializes those first.
        boolean resolved = ctx().classesWithClinit.contains(internalOwner);
        resolved |= inheritDepClinit(callerId, internalOwner);
        for (String sup : transSupers(internalOwner))
            if (!sup.equals(internalOwner)) resolved |= inheritDepClinit(callerId, sup);
        // NOTHING RESOLVED — not a project class, and no chained report carries its `<clinit>`. Touching
        // the class still RUNS that initializer, so this site reaches code the scan cannot see. Disclose it
        // as a κ blind spot, exactly as a direct CALL into the same package already is; without this the
        // forcing method is omitted from the report entirely, i.e. claimed pure.
        if (!resolved) kappaBlindOwner(callerId, internalOwner);
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
    /** ⟨0.29⟩ A JDBC PARAMETER BINDER — `setString`/`setObject`/`setNull`/… — whose String argument
     *  is a VALUE bound into a placeholder, never the query. Excluded from the table-literal window;
     *  see the call site for the measurement. `set…` is the closed JDBC naming convention for the
     *  whole family, and `setNull`/`setObject` are in it, so the prefix is the API's own boundary
     *  rather than a curated list that rots. */
    static boolean isSqlParameterBinder(String method) {
        return method.startsWith("set");
    }

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
        // A CHAINED DEPENDENCY'S type: candor's classpath cannot load it, so `transSupers` reads nothing and
        // this answered "not a stream" for every dep type — which is why the receiver-driven `w.write(..)`
        // reentry could not cross the scan boundary. The dep published its own hierarchy beside its report.
        // Kept as a SECOND walk rather than folded into `transSupers`, because that one feeds the project
        // subtype index (see Cha#depDirectSupers): the question here is only ever about a dep type, and
        // answering it must not change how a project type's dispatch resolves.
        if (ctx().depSupers.isEmpty()) return false;
        Set<String> seen = new HashSet<>();
        ArrayDeque<String> q = new ArrayDeque<>(ctx().depSupers.getOrDefault(internal, List.of()));
        while (!q.isEmpty()) {
            String t = q.poll();
            if (!seen.add(t)) continue;
            if (IO_STREAM_BASES.contains(t)) return true;
            q.addAll(Cha.depDirectSupers(t));
        }
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
        // PARAMETERIZED LOGGING (slf4j/log4j2/commons-logging/JUL). `LOGGER.warn("...{}", entry)` hands the
        // argument to the logging library as an Object and the library calls toString() on it INSIDE its own
        // formatter, at format time — so nothing in the caller's bytecode names `toString`, the JDK-facade
        // sinks above never match, and any effect reachable from the argument's toString() was SILENT.
        //
        // Found on HikariCP by the cross-organization confirmatory corpus (eval/corpus-crossorg): a
        // `ConcurrentBag.remove` reading (S={Log}, D=0) — sound-complete — while the run charged it Clock,
        // because PoolEntry.toString() calls currentTime(). A genuine false all-clear, and one silent in all
        // FOUR engines (candor-spec/SOUNDNESS-VEIN-implicit-stringify.md): what the engines share is not code
        // but the ASSUMPTION that stringification is pure.
        //
        // Matched by NAME + an Object-bearing descriptor rather than by exact owner, for the same reason
        // `isSyncCallbackInvoker` matches the forEach family owner-agnostically: the bytecode owner is
        // whichever Logger interface the project imported (org/slf4j/Logger, org/apache/logging/log4j/Logger,
        // a facade, a wrapper), and an owner-exact table silently misses the common case. Over-disclosure is
        // floored by `reentryEdge`, which resolves over the argument's declType and contributes NOTHING when
        // that type has no LOCAL toString override — so a String/boxed/JDK argument (the overwhelming
        // majority of log arguments) edges nowhere, and only a project type with its own toString does.
        if (LOG_LEVEL_NAMES.contains(name) && desc.contains("Ljava/lang/Object;")) return true;
        return false;
    }

    /** Level methods of the parameterized-logging facades (slf4j/log4j/commons-logging/JUL). Matched by name
     *  (see {@link #isToStringSink}); the Object-bearing-descriptor test is what keeps `warn(String)` and
     *  `isDebugEnabled()` out. */
    static final Set<String> LOG_LEVEL_NAMES =
            Set.of("trace", "debug", "info", "warn", "warning", "error", "fatal", "log", "severe", "config", "finest", "finer", "fine");

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
                if (ctx().byName.get(cName) == null) continue;
                // Each subtype contributes its OWN declarations AND the ones it INHERITS. Scanning only
                // `c.methods` fanned exclusively DOWN the subtype index, so a class overriding one overload
                // and inheriting the effectful other was silent: `new Formatter(half)` where
                // `Half extends Base` overrides `append(char)` still runs `Base.append(CharSequence)`, and
                // that body was never edged. (The fixed-descriptor branch below has always walked UP, via
                // `chaTargets` -> `nearestConcreteSuper`; only the by-NAME branch was one-directional. Found
                // when the CHAINED arm — which walks the dependency's supers — came out strictly MORE
                // complete than the in-scan control, which is the wrong way round.)
                //
                // Shadowing is per OVERLOAD, nearest-first, exactly as the cross-boundary
                // `nearestDepFnsNamed` resolves it: a project override of `append(char)` replaces THAT
                // descriptor and nothing else. Per NAME would drop the inherited overload (an under-report);
                // not at all would charge the replaced body (a fabrication). An ABSTRACT declaration settles
                // its descriptor without contributing — it overrides what is above it and redirects dispatch
                // to the concrete subtypes, which the subtype index enumerates separately.
                //
                // NEAREST is `Cha.resolutionOrder`'s order — the whole superclass chain before any
                // interface — because that is what the JVM does. By DEPTH, a nearer interface `default`
                // settled the descriptor and the superclass body two levels up was skipped as already
                // decided, so `new Formatter(half)` where `Half extends Mid implements Trace` charged
                // Trace's empty default and dropped `Root.append`'s Fs: a real effect read pure.
                Set<String> settled = new HashSet<>();
                for (String t : Cha.resolutionOrder(cName, true)) {
                    ClassNode c = ctx().byName.get(t);
                    // `byName` holds project classes alone, and a JDK/library body is not a project node to
                    // edge to — an external type contributes nothing and settles nothing, but the walk
                    // continues past it (a project class CAN sit above one in a partial scan).
                    if (c == null) continue;
                    for (MethodNode m : c.methods) {
                        if (!m.name.equals(contract) || (m.access & Opcodes.ACC_SYNTHETIC) != 0)
                            continue;                                 // skip bridges; edge the real impl(s)
                        if (!settled.add(m.desc)) continue;           // a nearer declaration won
                        if ((m.access & Opcodes.ACC_ABSTRACT) == 0)
                            out.add(methodId(c.name.replace('/', '.'), m.name, m.desc));
                    }
                }
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
    static boolean reentryEdge(String callerId, ProvValue argVal, String contract) {
        return reentryEdge(callerId, argVal, contract, true);
    }

    /** {@link #reentryEdge}, plus the κ DISCLOSURE when it resolved NOTHING.
     *
     *  A JDK sink re-entering user code (`"x" + w` compiles to `String.valueOf(w)` then a concat indy)
     *  runs the argument's `toString()`. If that type is neither a project class nor covered by a chained
     *  report, `reentryTargets` returns empty and `nearestDepFn` is null, so the site emitted NOTHING —
     *  and the concatenating method dropped out of `functions` altogether, a ⟨0.21⟩ purity claim over a
     *  body this scan never saw. Same defect as the static-read/`<clinit>` one, same repair: record the κ
     *  blind spot with the SAME predicate the call path uses, so a `java/lang/String` operand (κ-covered)
     *  records nothing and this cannot become a disclosure flood.
     *
     *  Only where `crossBoundary` holds — that flag marks the argument as provably the value whose
     *  contract runs, and disclosing against a value that may not be would over-report. */
    static void reentryEdgeOrDisclose(String callerId, ProvValue argVal, String contract) {
        if (!reentryEdge(callerId, argVal, contract, true) && argVal != null)
            kappaBlindOwner(callerId, argVal.declType);
    }

    /** {@link #reentryEdge}, with the cross-boundary half suppressible. {@code crossBoundary=false} keeps the
     *  in-scan CHA and skips the dependency join, for a sink whose argument is NOT provably the value whose
     *  contract runs (see {@link #comparesArgZero}). */
    static boolean reentryEdge(String callerId, ProvValue argVal, String contract, boolean crossBoundary) {
        if (argVal == null) return false;
        boolean resolved = false;
        for (String t : reentryTargets(argVal.declType, contract)) {
            ctx().edges.get(callerId).add(t);
            resolved = true;
        }
        // ACROSS THE SCAN BOUNDARY. `reentryTargets` ends in `chaTargets`, which scans PROJECT classes only
        // — so when the argument's declared type belongs to a chained DEPENDENCY it returns empty and the
        // site emitted nothing at all. `"x" + entry` on a dep type whose `toString()` reads the environment,
        // or `set.contains(depKey)` whose `equals` does, therefore read silent-pure — even though the dep's
        // own report carries that unit under exactly the hash we can compute here. Nothing looked for it.
        // This is the implicit-stringification / equals-reentry vein on the far side of the boundary
        // (candor-spec SOUNDNESS-VEIN-crossing-the-scan-boundary.md); the mechanism was closed INSIDE the
        // scan in all four engines, and stayed open across it, where it also flips the gate green.
        //
        // Inheritance, not an edge: the dep's unit lives in another report, so there is no node to edge to
        // — the same reason `inheritDepClinit` folds rather than edges. The FIXED-descriptor contracts
        // (toString/hashCode/equals) have an exact hash; the by-NAME contracts (compareTo/append/write/read)
        // resolve over ANY descriptor, so they enumerate the type's reported surface under that name
        // instead — see {@link #nearestDepFnsNamed} for the three guards that keeps it off a leaf-name join.
        if (!crossBoundary) return resolved;
        String depDesc = contract.equals(C_TOSTRING) ? "()Ljava/lang/String;"
                : contract.equals(C_HASHCODE) ? "()I"
                : contract.equals(C_EQUALS) ? "(Ljava/lang/Object;)Z" : null;
        if (depDesc != null) {
            DepFn d = nearestDepFn(argVal.declType, contract, depDesc);
            inheritDepFn(callerId, d);
            resolved |= d != null;
        } else {
            for (DepFn d : nearestDepFnsNamed(argVal.declType, contract)) {
                inheritDepFn(callerId, d);
                resolved = true;
            }
        }
        return resolved;
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

    /** ⟨timing⟩ OPT-IN PHASE TIMING, `CANDOR_TIMING=1`, stderr only.
     *
     *  <p>Written to answer one question with a measurement instead of an intuition: the agent
     *  edit-time loop pays a full re-analysis when one class changed, and the proposed fix is a
     *  per-class cache. That is only worth building if the time is actually spent PER CLASS. If the
     *  fixpoint dominates, a per-class cache buys little and the answer is elsewhere — so the phases
     *  must be separable before anyone writes a cache key.
     *
     *  <p>Off by default and on stderr, because this engine's contract is byte-equality between two
     *  routes: a timing line that could reach a report or a verdict would be a defect, not a
     *  diagnostic. Nanos, printed as millis, and it never throws — a broken timer must not fail a scan.
     */
    private static long timingMark = 0L;
    static boolean timingOn() {
        String v = System.getenv("CANDOR_TIMING");
        return v != null && !v.isEmpty() && !v.equals("0");
    }
    static void phase(String name) {
        if (!timingOn()) return;
        long now = System.nanoTime();
        if (timingMark != 0L) {
            System.err.printf("candor-timing  %-22s %8.1f ms%n", name, (now - timingMark) / 1e6);
        }
        timingMark = now;
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


    /** Record a κ BLIND SPOT for a NON-CALL site that provably reaches code this scan cannot see.
     *
     *  {@link #kappaLedger} is driven from a {@code MethodInsnNode}, so it only ever sees CALLS — and a
     *  STATIC FIELD READ is not one. {@code Object o = dep.Cls.V} forces the owner's {@code <clinit>}, and
     *  when that owner is neither a project class nor covered by a chained report, {@link #clinitEdge}
     *  resolved nothing and emitted nothing: the forcing method stayed ABSENT from {@code functions},
     *  which under ⟨0.21⟩ is a POSITIVE PURITY CLAIM over an initializer that may do anything.
     *
     *  MEASURED, app-only scan of a fixture whose dep class is absent: {@code viaDirectCall} and
     *  {@code viaExplicitToString} were PRESENT carrying {@code invisible:["dep"]} while the static-read
     *  forcer was absent altogether — the same blind spot, disclosed or not purely by whether the shape
     *  happened to be spelled as a call.
     *
     *  Deliberately the SAME predicate and the SAME accumulators the call path uses, so the tally keeps
     *  meaning "reaches whose effects this scan could not see", and the covered-prefix list keeps doing the
     *  work — a static read of {@code java.lang.Integer.MAX_VALUE} names a κ-COVERED package and records
     *  nothing, which is what stops this becoming a disclosure flood.
     *
     *  Only called where the site resolved NOTHING. A reach whose effects ARE on the record must not also
     *  be called invisible.
     *
     *  @return true if a blind spot was recorded. */
    static boolean kappaBlindOwner(String callerId, String internalOwner) {
        AnalysisContext c = ctx();
        if (internalOwner == null || internalOwner.isEmpty() || internalOwner.charAt(0) == '['
                || c.projectClasses.contains(internalOwner)) return false;
        int slash = internalOwner.lastIndexOf('/');
        String pkg = slash > 0 ? internalOwner.substring(0, slash).replace('/', '.') : "";
        if (pkg.isEmpty() || kappaCovers(pkg)) return false;
        // The PER-FUNCTION attribution is the point: without it the forcing method is omitted from
        // `functions` entirely, which under ⟨0.21⟩ claims it pure. The package also joins the report-level
        // ledger's LIST so `invisible` can never name a package `coverage.uncovered` omits — but NOT the
        // `calls` tally, which means call volume and drives the pinned completeness threshold.
        c.kappaBlindPkgs.add(pkg);
        c.blindDirect.computeIfAbsent(callerId, k -> new TreeSet<>()).add(pkg);
        return true;
    }

    static boolean kappaCovers(String pkg) {
        for (String p : KAPPA_COVERED_PREFIXES) {
            if (pkg.equals(p) || (pkg.length() > p.length() && pkg.charAt(p.length()) == '.' && pkg.startsWith(p))) return true;
        }
        return false;
    }

    /** An S3 transfer surface: the v1/v2 S3 service clients and the high-level TransferManager, whose
     *  File/Path overloads move bytes between the object store and the LOCAL filesystem. Deliberately
     *  narrower than the Net service rule — it gates on the s3 service package specifically, because the
     *  Fs claim is about S3's file overloads and not about every AWS client that happens to take a File. */
    static boolean isS3TransferOwner(String owner) {
        boolean s3Pkg = owner.startsWith("software.amazon.awssdk.services.s3.")
                || owner.startsWith("com.amazonaws.services.s3.")
                || owner.startsWith("software.amazon.awssdk.transfer.s3.");
        // THE OWNER GATE IS THE WHOLE RULE, and the Net rule beside this one already learned why: the
        // package is full of PURE value types that take a `File` and perform nothing —
        // `PutObjectRequest.withFile(f)` is a builder, not a transfer. Gating on the package alone
        // FABRICATED Fs on it (measured on a fixture: `build() -> ['Fs']`). The service rule's comment
        // records the same defect for Net on `AmazonS3URI.getBucket`; I read it and repeated it one rule
        // over, which is why this now mirrors its gate rather than inventing a looser one.
        return s3Pkg && (owner.endsWith("Client") || owner.endsWith("TransferManager"));
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
