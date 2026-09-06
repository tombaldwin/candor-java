package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R179 — A METHOD REFERENCE TO A FUNCTIONAL INTERFACE'S OWN SAM, HANDED TO A HIGHER-ORDER
 * FUNCTION, READ SILENT-PURE.
 *
 * <p><b>THE DEFECT.</b> {@code Optional.ofNullable(task).ifPresent(Runnable::run)},
 * {@code Stream.of(task).forEach(Runnable::run)}, {@code queue.forEach(Runnable::run)} and
 * {@code es.submit(task::run)} were ABSENT from the report, while the LAMBDA spelling of the same call —
 * {@code ifPresent(r -> r.run())} — discloses {@code Unknown} with
 * {@code callback:java.lang.Runnable.run}. One variable, the spelling. PUBLISHED: identical on 0.34.0 and
 * on the 0.35.0 candidate. Ground truth EXECUTED — every spelling really writes the file.
 *
 * <p><b>THE MECHANISM, and it is a comment asserting its own correctness (§E2/§K).</b>
 * {@code ProvValue#fromIndy} suppresses {@code Candor#opaqueTaskHandoff}'s {@code Unknown} on the stated
 * ground that a lambda's "body is edged at creation". For a reference to a functional interface's own SAM
 * that ground does not exist: the {@code LambdaMetafactory} handle names an ABSTRACT method
 * ({@code REF_invokeInterface java/lang/Runnable.run:()V}), so {@code handleInvokeDynamic}'s project
 * branch never runs (the owner is {@code java/lang/Runnable}, not a project class) and its external branch
 * finds nothing to classify or inherit. The body that really runs belongs to whatever receiver the
 * higher-order function supplies. The site therefore got neither an edge nor an Unknown.
 *
 * <p><b>NOT R84.</b> R84 is the same false premise one site over — {@code indyLambdaTarget} accepting an
 * abstract PROJECT method-ref as a clean lambda body, for a FIELD-BOUND dispatch. It fixed the project
 * branch and left the suppression at the hand-off site untouched, which is §F1 q3 (two implementations of
 * one question, drifting) crossed with q2 (a callable target with no body).
 *
 * <p><b>WHY THE SAM TABLE RATHER THAN "IS THE TARGET ABSTRACT".</b> {@code Candor#handleTargetConcrete}
 * fails CLOSED for every non-project owner — it can only read {@code ACC_ABSTRACT} off a LOADED project
 * class — so reusing it here would call {@code System.out::println} bodiless too and disclose
 * {@code Unknown} over provably pure code. {@code aConcreteJdkMethodReferenceIsStillPure} is that control,
 * and it is the row that would have caught the wrong fix.
 *
 * <p><b>REAL CODE, found by the corpus A/B rather than by enumeration:</b> spring-web 5.3.39's
 * {@code StandardServletAsyncWebRequest.onTimeout} and {@code .onComplete} are literally
 * {@code this.timeoutHandlers.forEach(Runnable::run)} — confirmed from the class file's own
 * {@code BootstrapMethods} table — and both are ENTRY POINTS (servlet {@code AsyncListener} callbacks), so
 * a user's registered timeout handler ran through a method certified pure.
 */
class SamForwarderHandoffTest {

    private static final String STORE = String.join("\n",
        "package app;",
        "import java.nio.file.*;",
        "public class Store {",
        "  public void write() { try { Files.writeString(",
        "      Paths.get(System.getProperty(\"candor.r179.witness\")), \"x\",",
        "      StandardOpenOption.CREATE, StandardOpenOption.APPEND); }",
        "    catch (Exception e) { throw new RuntimeException(e); } }",
        "}");

    /** The five spellings, deliberately named so that NO NAME IS A PREFIX OF ANOTHER — the 0.35.0 panel
     *  recorded a cell contaminated by scope prefix-matching (`fireForEach` against `fireForEachLambda`),
     *  and a scoped policy in this file would inherit exactly that. */
    private static final String WIDGET = String.join("\n",
        "package app;",
        "import java.util.*;",
        "import java.util.function.Consumer;",
        "import java.util.stream.Stream;",
        "public class Widget {",
        "  private Runnable task;",
        "  private final List<Runnable> queue = new ArrayList<>();",
        "  public void install(Store s) { Runnable r = () -> s.write(); this.task = r; queue.add(r); }",
        "  public void viaOptional() { Optional.ofNullable(task).ifPresent(Runnable::run); }",
        "  public void viaStream()   { Stream.of(task).forEach(Runnable::run); }",
        "  public void viaList()     { queue.forEach(Runnable::run); }",
        "  public void withLambda()  { Optional.ofNullable(task).ifPresent(r -> r.run()); }",
        "  public void plainLoop()   { for (Runnable r : queue) r.run(); }",
        "  public void printAll(List<String> xs) { xs.forEach(System.out::println); }",
        "}");

    private static final String MAIN = String.join("\n",
        "package app;",
        "public class Main { public static void main(String[] a) {",
        "  Widget w = new Widget(); w.install(new Store());",
        "  w.viaOptional(); w.viaStream(); w.viaList();",
        "} }");

    private static Map<String, String> fixture() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Store.java", STORE);
        m.put("app/Widget.java", WIDGET);
        m.put("app/Main.java", MAIN);
        return m;
    }

    /** RED without the fix on all three rows: each is ABSENT from the report entirely, and
     *  {@code deny Unknown app.Widget.viaOptional} goes exit 0 over a method that really runs the
     *  stored task. */
    @Test
    void aMethodReferenceToAFunctionalInterfaceSamIsDisclosedNotSilent() throws Exception {
        Path cls = compile(fixture());
        try {
            // §E3 — GROUND TRUTH FIRST. The three spellings are RUN, and each really performs the write.
            // Without this the absence rows below could not tell a correct engine from a broken one.
            Path witness = Files.createTempFile("candor-r179", ".txt");
            Files.delete(witness);
            String saved = System.getProperty("candor.r179.witness");
            System.setProperty("candor.r179.witness", witness.toString());
            try (URLClassLoader cl = new URLClassLoader(new URL[]{cls.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                cl.loadClass("app.Main").getMethod("main", String[].class).invoke(null, (Object) new String[0]);
            } finally {
                if (saved == null) System.clearProperty("candor.r179.witness");
                else System.setProperty("candor.r179.witness", saved);
            }
            assertEquals("xxx", Files.readString(witness),
                "all three method-reference spellings must really perform the effect — three writes, one "
                + "per spelling. Anything else and the engine rows below are measured against the wrong "
                + "program");
            Files.deleteIfExists(witness);

            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"viaOptional", "viaStream", "viaList"}) {
                assertTrue(eff(r, "app.Widget." + m).contains(Effect.UNKNOWN),
                    m + " hands an OPAQUE task to a higher-order function through a method reference that "
                    + "names no body — it must disclose, never read pure. Got " + r.get("app.Widget." + m));
                assertTrue(why(m).contains("callback:java.lang.Runnable.run"),
                    m + " must disclose the SAME reason the LAMBDA spelling of the same call produces, so "
                    + "the two are not merely both non-silent but identical in the disclosure channel. Got "
                    + why(m));
            }
        } finally { rm(cls.getParent()); }
    }

    /** THE ONE-VARIABLE CONTROL. The lambda spelling was already disclosed and must stay exactly as it
     *  was — it is what makes "the spelling is the only difference" a measurement rather than a claim.
     *  Passes in BOTH arms by construction. */
    @Test
    void theLambdaSpellingAndThePlainLoopAreUnchanged() throws Exception {
        Path cls = compile(fixture());
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Widget.withLambda").contains(Effect.UNKNOWN),
                "the lambda spelling disclosed before this fix and must still: " + r.get("app.Widget.withLambda"));
            assertTrue(eff(r, "app.Widget.plainLoop").contains(Effect.UNKNOWN),
                "so must the plain loop over the same field: " + r.get("app.Widget.plainLoop"));
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL, and the row that discriminates this fix from the WRONG one.
     *  {@code System.out::println} is a method reference to a CONCRETE JDK method: its body exists, the
     *  classifier's own answer for it is the authority, and nothing here may disclose {@code Unknown} over
     *  it. A fix keyed on {@code handleTargetConcrete} (which fails closed for every non-project owner)
     *  would turn this row red — which is why the predicate is keyed on {@code SAM_OF} instead. */
    @Test
    void aConcreteJdkMethodReferenceIsStillPure() throws Exception {
        Path cls = compile(fixture());
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "app.Widget.printAll").contains(Effect.UNKNOWN),
                "xs.forEach(System.out::println) names a CONCRETE body — disclosing Unknown here would be "
                + "a fabrication on provably pure code. Got " + r.get("app.Widget.printAll"));
        } finally { rm(cls.getParent()); }
    }

    /** §9 — THE SIBLING SITES THE TRIGGER DID NOT NAME. The same bodiless reference reaches
     *  {@code opaqueTaskHandoff} through the EXECUTOR arm as well as the sync-callback arm, and in the
     *  BOUND form ({@code act::run}) rather than the unbound one — bound or unbound makes no difference,
     *  because either way the constant-pool target is an abstract declaration. Both were silent. */
    @Test
    void theExecutorAndThreadArmsAreCoveredToo() throws Exception {
        Path cls = compile(Map.of("app/Edge.java", String.join("\n",
            "package app;",
            "import java.util.concurrent.ExecutorService;",
            "public class Edge {",
            "  private Runnable act;",
            "  public void submitRef(ExecutorService es) { es.submit(act::run); }",
            "  public void threadRef() { new Thread(act::run).start(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"submitRef", "threadRef"})
                assertTrue(eff(r, "app.Edge." + m).contains(Effect.UNKNOWN),
                    m + " hands a bodiless SAM reference to a runtime that invokes it — must disclose. Got "
                    + r.get("app.Edge." + m));
        } finally { rm(cls.getParent()); }
    }

    /** A BOUND reference to a CONCRETE PROJECT method must still RESOLVE to that body — this fix removes a
     *  wrong suppression, it must not remove a right resolution. {@code Toggle.go} is the field-stored
     *  method-ref toggle PART 87 closed at HEAD (it was `Unknown` on published 0.34.0); it must stay
     *  {@code Fs}, not regress to a disclosure. Passes in BOTH arms by construction. */
    @Test
    void aBoundProjectMethodReferenceStillResolvesToItsBody() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Store.java", STORE);
        m.put("app/Toggle.java", String.join("\n",
            "package app;",
            "public class Toggle {",
            "  private Runnable act;",
            "  public void bind(Store s) { this.act = s::write; }",
            "  public void go() { act.run(); }",
            "}"));
        Path cls = compile(m);
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Toggle.go").contains(Effect.FS),
                "the field-bound method reference resolves to Store.write and must keep doing so: "
                + r.get("app.Toggle.go"));
            assertFalse(eff(r, "app.Toggle.go").contains(Effect.UNKNOWN),
                "…and must not be DOWNGRADED to a disclosure by this fix: " + r.get("app.Toggle.go"));
        } finally { rm(cls.getParent()); }
    }

    /** THE BOUNDARY, MOVED AGAIN — this row was {@code theHofTableBoundaryThisRowDoesNotWiden}, then
     *  {@code theRemainingBoundaryIsTheOPAQUECallbackNotTheSpelling}, and SOUNDNESS R217 made THAT
     *  boundary obsolete rather than merely crossing it.
     *
     *  <p><b>What it used to pin.</b> After R183 closed the SPELLING gap at the creation site, a callback
     *  arriving as a FIELD or a PARAMETER still had no creation site to attribute anything to, so
     *  {@code xs.removeIf(pParam)} and {@code m.computeIfAbsent(k, fnParam)} stayed silent. R217 closed
     *  that, in {@link OpaqueCallbackToHofTest}, and <b>without widening either invoker table</b>:
     *  {@code Candor#isInvokingHof} was already the authority for "does this library higher-order
     *  function invoke the functional argument it is handed", answering exactly that question at exactly
     *  this call site for the {@code new EffImpl()} arm.
     *
     *  <p><b>What the boundary actually is, now that opaqueness no longer decides.</b> THE INTERFACE SET.
     *  Every arm that charges a callback — the lambda body's unpinned-SAM read, R183's creation-site arm,
     *  and now the opaque arm — is keyed on {@code java/util/function/} + {@code Runnable} +
     *  {@code Callable}. A {@code Comparator} is outside all three, so {@code xs.sort(cmpField)} is
     *  silent, and so is {@code cmpParam.compare(a, b)} — the SAME callback invoked directly, one frame
     *  shallower, with no higher-order function involved at all. That is a live silent under-report and
     *  it is R183's stated residual (2): closing it means widening {@code Candor#isJdkFunctionalSam} for
     *  EVERY arm together, which is a separate row with its own fabrication risk — the wider set was
     *  built and measured for R217 and cost +1,697 rows over 395 jars, 596 in assertj-core alone.
     *
     *  <p>Pinned exactly as before: when it is closed, this row goes RED and the register moves with it.
     *  {@code removeArm} is the control that keeps the two questions apart — the same OPAQUE parameter at
     *  the same kind of higher-order function, differing only in the interface, disclosed since R217. */
    @Test
    void theRemainingBoundaryIsTheInterfaceSetNotTheOpaqueness() throws Exception {
        Path cls = compile(Map.of("app/Opaque.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.*;",
            "public class Opaque {",
            "  private Comparator<String> cmp;",
            "  public void sortField(List<String> xs) { xs.sort(cmp); }",
            "  public void sortParam(List<String> xs, Comparator<String> c) { xs.sort(c); }",
            "  public Optional<String> minParam(List<String> xs, Comparator<String> c) { return xs.stream().min(c); }",
            "  public int compareParam(Comparator<String> c) { return c.compare(\"a\", \"b\"); }",
            "  public boolean removeArm(List<String> xs, Predicate<String> p) { return xs.removeIf(p); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"sortField", "sortParam", "minParam", "compareParam"})
                assertFalse(eff(r, "app.Opaque." + m).contains(Effect.UNKNOWN),
                    "RESIDUAL, NOT A CLAIM OF CORRECTNESS: " + m + " reaches a Comparator that really "
                    + "runs, and Comparator is outside `isJdkFunctionalSam` — the set EVERY arm that "
                    + "charges a callback is keyed on — so it is silent whether it is handed to a "
                    + "higher-order function or invoked directly. An OPEN silent under-report, and the "
                    + "one that really does need the interface set widened for all arms at once. Got "
                    + r.get("app.Opaque." + m));
            assertTrue(eff(r, "app.Opaque.removeArm").contains(Effect.UNKNOWN),
                "…and the CONTROL that separates the two: the same OPAQUE parameter at the same kind of "
                + "higher-order function, differing only in the interface, which R217 discloses. If this "
                + "went silent the four rows above would read as a boundary when they were really a "
                + "regression. Got " + r.get("app.Opaque.removeArm"));
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** The rendered {@code unknownWhy} strings recorded for {@code app.Widget.<m>} by the scan just run. */
    private static String why(String m) {
        TreeSet<UnknownReason> s = AnalysisState.ctx().unknownWhy.get("app.Widget." + m);
        return s == null ? "<none>" : s.toString();
    }
}
