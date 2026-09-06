package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.compileApp;
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
 * SOUNDNESS R237 — AN INVOKING HIGHER-ORDER FUNCTION {@code isInvokingHof} DOES NOT NAME IS SILENT, EVEN
 * FOR AN INTERFACE THE SET DOES COVER.
 *
 * <p><b>THE DEFECT, GROUND TRUTH EXECUTED against a jar built at {@code 61fb0b4}</b> (R236's commit, so
 * the interface set is already the wide one and cannot be the cause). {@code Optional.orElseGet(supParam)}
 * and {@code Objects.requireNonNullElseGet(x, supParam)} are ABSENT from {@code functions[]} while
 * {@code List.removeIf(pParam)} in the same class discloses
 * {@code callback:java.util.function.Predicate.test}. {@code Supplier} is inside the interface set, so
 * the gate is not the problem; the HOF is. {@code Candor#isInvokingHof} is a hand-written ALLOWLIST of 27
 * simple names, and an allowlist fails toward SILENCE.
 *
 * <p><b>THE ENUMERATION IS THE WORK, NOT THE MECHANISM.</b> What R237 asks for is a swept list of JDK
 * HOFs that invoke their functional argument, not another one-at-a-time addition — and the swept answer
 * is not a list a person can write, because it depends on bodies: {@code List.sort} does not invoke the
 * comparator, it forwards it to {@code Arrays.sort}, which forwards to {@code TimSort.sort}, which
 * forwards to {@code binarySort}, which invokes it. So {@code generateJdkHofInvokes} in build.gradle.kts
 * asks the JDK (§G): ASM's own {@code SourceInterpreter} over every JDK method that takes a
 * functional-interface parameter, plus a fixpoint through the forwarding edges. 1,623 (name, descriptor)
 * entries, 412 simple names {@code isInvokingHof} never had.
 *
 * <p><b>TWO SHAPES THE SWEEP HAS TO SEE THROUGH, AND BOTH ARE DERIVED RATHER THAN LISTED.</b> A CHECKCAST
 * between the wrapper and the call (erasure), and an IDENTITY WRAPPER — a small method whose every
 * {@code ARETURN} returns one of its own arguments. {@code Objects.requireNonNullElseGet} needs both: its
 * {@code supplier.get()} receiver is {@code (Supplier) requireNonNull(supplier, "supplier")}. Hand-listing
 * {@code Objects.requireNonNull} instead would have been the second authority this sweep exists to avoid.
 *
 * <p><b>UNIONED WITH THE NAME LIST, NEVER SUBSTITUTED FOR IT.</b> An abstract interface method whose
 * implementation wraps the callback in a lazy pipeline has no body for the sweep to read —
 * {@code Stream.map} is the case, and {@code theIndexIsUnionedWithTheNameListNotSubstitutedForIt} is what
 * fails if that stops being true.
 *
 * <p><b>WHICH DIRECTION IT FAILS IN, SAID BEFORE THE CHANGE.</b> A method the sweep cannot prove invoking
 * is ABSENT, and absent is the pre-R237 answer — so the change is additive and {@code REMOVED} had to be
 * 0. What it can get WRONG is a (name, descriptor) collision with a non-JDK method that merely stores its
 * callback: an OVER-report, bounded by the caller's other gate, which still requires the argument's
 * declared type to be one {@code isFunctionalIface} recognises. That bound is measured, not asserted:
 * over 395 jars the index admitted {@code String.join(CharSequence, Iterable)} 65 times,
 * {@code CollectionsKt.toSet(Iterable)} 39 times and {@code IOUtils.close(Closeable)} 7 times, and every
 * one of those charged NOTHING because {@code Iterable} and {@code Closeable} are not in the owner list.
 * {@code theInterfaceGateStillBoundsTheIndexsReach} is that control.
 *
 * <p><b>A/B OVER 395 GRADLE-CACHE JARS, KEYED ON EVERY FIELD, 580,538 COMMON ROWS: ADDED 290, REMOVED 0,
 * CHANGED(every field) 481, CHANGED(inferred) 195.</b> Instrumented: 1,669 events at 1,361 distinct sites,
 * so the new branch really runs on real code. No channel lost an entry except {@code overdeclared} (96
 * rows), which is {@code declared - performed} shrinking because {@code performed} grew. The largest
 * cluster is commons-lang3 (122 + 99 rows across two versions) and it is ONE shape:
 * {@code Validate.notNull(obj, msg, values)} compiles to
 * {@code Objects.requireNonNull(obj, toSupplier(msg, values))}, so the supplier is a CALL RETURN — R217's
 * residual (3), disclosed rather than resolved, and it propagates through a library everything uses.
 * Stated rather than implied.
 *
 * <p><b>THE RECALL, GROUND-TRUTHED FROM {@code javap}.</b> undertow's
 * {@code GSSAPIAuthenticationMechanism.runGSSAPI} does {@code new AcceptSecurityContext(...)} then
 * {@code Subject.doAs(subject, action)} — a name {@code isInvokingHof} never had — and gained
 * {@code Clock} and {@code Rand} from the action's own body. That is a CONCRETE effect the engine had
 * been dropping entirely, and it is the only row in the whole A/B that gained one.
 */
class JdkHofIndexTest {

    private static final String EFF = String.join("\n",
        "package app;",
        "import java.nio.file.*;",
        "public class Eff {",
        "  public static void touch() { try { Files.writeString(",
        "      Paths.get(System.getProperty(\"candor.r237.witness\")), \"x\",",
        "      StandardOpenOption.CREATE, StandardOpenOption.APPEND); }",
        "    catch (Exception e) { throw new RuntimeException(e); } }",
        "}");

    /** Every callback arrives as a PARAMETER, and no class here implements any functional interface, so
     *  CHA is empty and a disclosure is the only honest answer. {@code control} is the discriminator: the
     *  same interface at a HOF the name list already had. */
    private static final String HOF = String.join("\n",
        "package app;",
        "import java.util.*;",
        "import java.util.function.*;",
        "public class Hof {",
        "  public String orElseGet(Optional<String> o, Supplier<String> s)      { return o.orElseGet(s); }",
        "  public String elseGetNull(String x, Supplier<String> s)              { return Objects.requireNonNullElseGet(x, s); }",
        "  public String thenApplied(java.util.concurrent.CompletableFuture<String> f, Function<String,String> g) { return f.thenApply(g).join(); }",
        "  public boolean control(List<String> xs, Predicate<String> p)         { return xs.removeIf(p); }",
        "}");

    private static final String DRIVE = String.join("\n",
        "package app;",
        "import java.util.*;",
        "import java.util.concurrent.*;",
        "import java.util.function.*;",
        "public class Drive { public static void main(String[] a) {",
        "  Hof h = new Hof();",
        "  h.orElseGet(Optional.empty(), () -> { Eff.touch(); return \"x\"; });",
        "  h.elseGetNull(null, () -> { Eff.touch(); return \"x\"; });",
        "  h.thenApplied(CompletableFuture.completedFuture(\"x\"), s -> { Eff.touch(); return s; });",
        "  h.control(new ArrayList<>(List.of(\"z\")), s -> { Eff.touch(); return false; });",
        "} }");

    private static final String[] ARMS = {"orElseGet", "elseGetNull", "thenApplied", "control"};

    /** RED WITHOUT THE FIX: {@code orElseGet}, {@code elseGetNull} and {@code thenApplied} are ABSENT on a
     *  jar built at {@code 61fb0b4}; {@code control} is {@code Unknown} on both, which is what makes the
     *  other three a HOF question and not an interface one.
     *
     *  <p>§E3/§J — GROUND TRUTH EXECUTED. All four arms run and each performs one write.
     *
     *  <p>DISCRIMINATING: removing {@code jdkInvokesAnyFunctionalArg} from the gate reddens the first
     *  three and leaves {@code control} green. */
    @Test
    void anInvokingHofTheNameListNeverHadIsDisclosedNotSilent() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Eff.java", EFF);
        m.put("app/Hof.java", HOF);
        m.put("app/Drive.java", DRIVE);
        Path cls = compile(m);
        try {
            Path witness = Files.createTempFile("candor-r237", ".txt");
            Files.delete(witness);
            String saved = System.getProperty("candor.r237.witness");
            System.setProperty("candor.r237.witness", witness.toString());
            try (URLClassLoader cl = new URLClassLoader(new URL[]{cls.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                cl.loadClass("app.Drive").getMethod("main", String[].class).invoke(null, (Object) new String[0]);
            } finally {
                if (saved == null) System.clearProperty("candor.r237.witness");
                else System.setProperty("candor.r237.witness", saved);
            }
            assertEquals("xxxx", Files.readString(witness),
                "the four arms must really perform the effect — one write each — or every row below is "
                + "measured against a program that does not do what this row says it does");
            Files.deleteIfExists(witness);

            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String a : ARMS)
                assertTrue(eff(r, "app.Hof." + a).contains(Effect.UNKNOWN),
                    a + " hands a caller-supplied callback to a JDK method that really invokes it — the "
                    + "run just proved it writes a file. Got " + r.get("app.Hof." + a));
            assertEquals("[callback:java.util.function.Supplier.get]", whyOf("app.Hof.orElseGet"),
                "and the reason names the interface the JDK really invokes, byte-identical to what the "
                + "HOFs the name list already had produce");
            assertEquals("[callback:java.util.function.Supplier.get]", whyOf("app.Hof.elseGetNull"),
                "including the one that needs BOTH the identity-wrapper and the CHECKCAST rules: the "
                + "receiver of `supplier.get()` there is `(Supplier) requireNonNull(supplier, ...)`");
        } finally { rm(cls.getParent()); }
    }

    /** THE INDEX IS BUNDLED AND ANSWERS THE CELLS THIS ROW IS ABOUT. Without this, a build that failed to
     *  generate or bundle the resource degrades SILENTLY to {@code isInvokingHof} alone — which is exactly
     *  the pre-R237 answer, so nothing else in the suite would notice.
     *
     *  <p>{@code ifPresentOrElse} is here as a REGRESSION GUARD on a bug the sweep really had: ASM's
     *  operand stack is VALUE-indexed, not slot-indexed, so summing {@code Type.getSize()} to find the
     *  receiver put it one entry too low for every call with a {@code long} or {@code double} argument.
     *  {@code OptionalDouble.ifPresentOrElse(DoubleConsumer, Runnable)} came back naming only the
     *  {@code Runnable}; counted rather than sized it names both, and 155 further entries appeared. */
    @Test
    void theIndexIsBundledAndAnswersTheHofsThisRowIsAbout() {
        assertTrue(Candor.class.getResource("/candor/jdk-hof-invokes.idx.gz") != null,
            "the build-time JDK invoking-HOF index must be on the classpath — without it the gate "
            + "degrades to isInvokingHof and every cell this row is about goes silent again");
        assertTrue(Candor.jdkInvokesFunctionalArg("orElseGet", "(Ljava/util/function/Supplier;)Ljava/lang/Object;", 0),
            "Optional.orElseGet really invokes its supplier");
        assertTrue(Candor.jdkInvokesFunctionalArg("requireNonNullElseGet",
                "(Ljava/lang/Object;Ljava/util/function/Supplier;)Ljava/lang/Object;", 1),
            "Objects.requireNonNullElseGet really invokes its supplier — through an identity wrapper and "
            + "a CHECKCAST, which is why the sweep has to see through both");
        for (String iface : new String[] {"Consumer", "DoubleConsumer", "IntConsumer", "LongConsumer"}) {
            String desc = "(Ljava/util/function/" + iface + ";Ljava/lang/Runnable;)V";
            assertTrue(Candor.jdkInvokesFunctionalArg("ifPresentOrElse", desc, 0)
                    && Candor.jdkInvokesFunctionalArg("ifPresentOrElse", desc, 1),
                "ifPresentOrElse invokes BOTH arguments. The primitive overloads are the regression guard "
                + "for the value-vs-slot indexing bug: sized rather than counted, the DoubleConsumer arm "
                + "was invisible. Missing for " + iface);
        }
        assertFalse(Candor.jdkInvokesFunctionalArg("withInitial",
                "(Ljava/util/function/Supplier;)Ljava/lang/ThreadLocal;", 0),
            "ThreadLocal.withInitial STORES its supplier for later — the sweep must not claim it runs "
            + "one, or the index becomes a fabrication generator rather than a recall one");
    }

    /** THE INDEX IS UNIONED WITH THE NAME LIST, NOT SUBSTITUTED FOR IT. {@code Stream.map} is abstract on
     *  the interface and its implementation stores the mapper in a lazy pipeline, so there is no body for
     *  the sweep to read and the index does not name it. The hand list does, and dropping the hand list
     *  would therefore be the SILENT direction.
     *
     *  <p>DISCRIMINATING: replacing the gate's {@code nameHof ||} with the index alone reddens this row. */
    @Test
    void theIndexIsUnionedWithTheNameListNotSubstitutedForIt() throws Exception {
        assertFalse(Candor.jdkInvokesFunctionalArg("map",
                "(Ljava/util/function/Function;)Ljava/util/stream/Stream;", 0),
            "premise of this row: the sweep genuinely cannot see Stream.map, because the mapper is only "
            + "invoked inside an anonymous pipeline op in another class");
        Path cls = compile(Map.of("app/Lazy.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.*;",
            "import java.util.stream.*;",
            "public class Lazy {",
            "  public List<String> mapped(List<String> xs, Function<String,String> f) {",
            "    return xs.stream().map(f).collect(Collectors.toList()); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Lazy.mapped").contains(Effect.UNKNOWN),
                "Stream.map really runs the mapper, the hand list is the only thing that knows it, and "
                + "the union is what keeps that true. Got " + r.get("app.Lazy.mapped"));
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL. Every sink here takes a genuinely functional-TYPED parameter — so the
     *  interface gate really is consulted, unlike an {@code Object}-erased sink, which is the trap R217
     *  recorded — and none of them invokes it now: {@code ThreadLocal.withInitial} and
     *  {@code Collectors.groupingBy} store it, {@code Comparator.comparing} and {@code Function.andThen}
     *  and {@code Predicate.and} wrap it into a new function, and {@code new TreeMap<>(cmp)} keeps it.
     *
     *  <p>DISCRIMINATING, AND THE FIRST DEGRADATION I TRIED DID NOT WORK — recorded because a claim like
     *  this reads as coverage whether or not anyone ran it. Forcing {@code jdkInvokesAnyFunctionalArg}
     *  true leaves this row GREEN: the outer gate only decides whether the per-argument loop is entered,
     *  and {@code jdkInvokesFunctionalArg} still says no for every sink here. Forcing
     *  {@code jdkInvokesFunctionalArg} alone leaves it green too, for the mirror reason. It reddens when
     *  BOTH answer true — i.e. when there is no sweep at all and every functional argument of every
     *  external call is charged, which is the shape this index exists to avoid. */
    @Test
    void aStoringOrWrappingSinkGainsNothing() throws Exception {
        Path cls = compile(Map.of("app/Sink.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.*;",
            "import java.util.stream.*;",
            "public class Sink {",
            "  public ThreadLocal<String> lazy(Supplier<String> s)              { return ThreadLocal.withInitial(s); }",
            "  public Object grouping(Function<String,String> f)                { return Collectors.groupingBy(f); }",
            "  public Comparator<String> comparing(Function<String,String> f)   { return Comparator.comparing(f); }",
            "  public Function<String,String> chain(Function<String,String> f, Function<String,String> g) { return f.andThen(g); }",
            "  public Predicate<String> both(Predicate<String> p, Predicate<String> q) { return p.and(q); }",
            "  public Map<String,String> tree(Comparator<String> c)             { return new TreeMap<>(c); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"lazy", "grouping", "comparing", "chain", "both", "tree"})
                assertFalse(eff(r, "app.Sink." + m).contains(Effect.UNKNOWN),
                    m + " hands its callback to a JDK method that STORES or WRAPS it and does not run it "
                    + "here. The sweep reads bodies, so it must not name these. Got " + r.get("app.Sink." + m));
        } finally { rm(cls.getParent()); }
    }

    /** THE INTERFACE GATE STILL BOUNDS THE INDEX'S REACH, AND THAT IS THE ANSWER TO THE COLLISION RISK.
     *  The index is keyed by (name, descriptor) with no owner, so a non-JDK method of the same shape
     *  matches it. That is deliberate — an owner-keyed index would need a runtime resolution walk and
     *  would go silent wherever it missed — and the bound is the OTHER gate: the argument's declared type
     *  must be one {@code isFunctionalIface} recognises.
     *
     *  <p>{@code String.join(CharSequence, Iterable)} is the measured case rather than a hypothetical:
     *  {@code Iterable} is a functional interface, the sweep names it (the JDK really calls
     *  {@code iterator()}), and over 395 jars the gate admitted this call 65 times and charged NOTHING
     *  every time. Charging it would be the {@code map(Iterable::iterator)} fabrication R183 measured and
     *  declined.
     *
     *  <p>DISCRIMINATING: widening {@code isFunctionalIface} to {@code samNameOf}'s 732-interface index
     *  reddens this row. */
    @Test
    void theInterfaceGateStillBoundsTheIndexsReach() throws Exception {
        assertTrue(Candor.jdkInvokesFunctionalArg("join",
                "(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;", 1),
            "premise of this row: the sweep DOES name String.join's Iterable, so the interface gate is "
            + "the only thing standing between it and a charge");
        Path cls = compile(Map.of("app/Join.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "public class Join {",
            "  public String join(Iterable<String> xs) { return String.join(\",\", xs); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "app.Join.join").contains(Effect.UNKNOWN),
                "Iterable is not an interface candor charges a callback for — its `iterator()` is an "
                + "ordinary classified JDK call, and charging it here would fabricate on the front door "
                + "of every collection API. Got " + r.get("app.Join.join"));
        } finally { rm(cls.getParent()); }
    }

    /** THE INDEX IS CONSULTED PER ARGUMENT, NOT PER CALL, AND THAT MATTERS WHERE ONE OF TWO CALLBACKS IS
     *  MERELY STORED. The callee is an EXTERNAL library method (compiled to a separate directory that is
     *  never scanned) whose name and descriptor collide with a JDK entry the sweep resolved to argument 2
     *  ALONE — the http-client's {@code sendPong(Supplier, Object, BiConsumer)}, which stores the supplier
     *  and invokes the BiConsumer. So the BiConsumer must charge and the Supplier must not.
     *
     *  <p>DISCRIMINATING: dropping the per-argument {@code jdkInvokesFunctionalArg} check (charging every
     *  functional argument of an index-named call) reddens the Supplier assertion. */
    @Test
    void theIndexIsConsultedPerArgumentNotPerCall() throws Exception {
        assertTrue(Candor.jdkInvokesFunctionalArg("sendPong",
                "(Ljava/util/function/Supplier;Ljava/lang/Object;Ljava/util/function/BiConsumer;)"
                + "Ljava/util/concurrent/CompletableFuture;", 2),
            "premise: the sweep resolved argument 2 of this shape");
        assertFalse(Candor.jdkInvokesFunctionalArg("sendPong",
                "(Ljava/util/function/Supplier;Ljava/lang/Object;Ljava/util/function/BiConsumer;)"
                + "Ljava/util/concurrent/CompletableFuture;", 0),
            "…and NOT argument 0, which the JDK stores rather than runs");
        Map<String, String> lib = Map.of("lib/Ws.java", String.join("\n",
            "package lib;",
            "import java.util.concurrent.*;",
            "import java.util.function.*;",
            "public class Ws {",
            "  public static <T> CompletableFuture<T> sendPong(Supplier<T> s, Object o, BiConsumer<T,Object> c) {",
            "    return null; }",
            "}"));
        Map<String, String> app = Map.of("app/Use.java", String.join("\n",
            "package app;",
            "import lib.Ws;",
            "import java.util.function.*;",
            "public class Use {",
            "  public Object send(Supplier<String> s, BiConsumer<String,Object> c) { return Ws.sendPong(s, \"x\", c); }",
            "}"));
        Path cls = compileApp(lib, app);
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Use.send").contains(Effect.UNKNOWN),
                "the BiConsumer at argument 2 really runs. Got " + r.get("app.Use.send"));
            assertEquals("[callback:java.util.function.BiConsumer.accept]", whyOf("app.Use.send"),
                "and EXACTLY that one reason. A per-CALL gate would add "
                + "`callback:java.util.function.Supplier.get` for an argument the callee only stores — "
                + "which is the fabrication direction, on a site the index itself says is safe");
            // `compileApp` returns `<temp>/app`, so its PARENT is the fixture root. `getParent()
            // .getParent()` would be the system temp directory itself — which this row did, once,
            // and it deleted a gate run's log directory out from under it.
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** The rendered {@code unknownWhy} strings recorded for {@code fn} by the scan just run. */
    private static String whyOf(String fn) {
        TreeSet<UnknownReason> s = AnalysisState.ctx().unknownWhy.get(fn);
        return s == null ? "<none>" : s.toString();
    }
}
