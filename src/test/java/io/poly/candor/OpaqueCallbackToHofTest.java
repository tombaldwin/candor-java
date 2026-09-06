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
 * SOUNDNESS R217 — AN OPAQUE CALLBACK (ONE ARRIVING AS A FIELD OR A PARAMETER) HANDED TO A HIGHER-ORDER
 * FUNCTION READ SILENT-PURE, WHILE ITS LAMBDA AND METHOD-REFERENCE TWINS DISCLOSED.
 *
 * <p><b>THE DEFECT, GROUND TRUTH EXECUTED.</b> {@code xs.removeIf(pParam)} and
 * {@code m.computeIfAbsent(k, fnParam)} are ABSENT from {@code functions[]} on the pre-fix engine, while
 * the run really performs the effect — five writes, one per driven arm. {@code deny Unknown} over those
 * methods exits 0 "no violations". The one-variable twins {@code xs.removeIf(x -> p.test(x))} and
 * {@code xs.removeIf(p::test)} are {@code ['Unknown']} on the SAME engine, so the silence is not a
 * stance about higher-order functions — it is a hole under one spelling.
 *
 * <p><b>THE ROW'S PREMISE WAS HALF WRONG, AND THAT MATTERS FOR WHAT GETS FIXED.</b> R217 says the site is
 * "silent in EVERY spelling". Measured on the shipped engine, that is TRUE for {@code xs.sort(cmpField)}
 * and FALSE for {@code removeIf} / {@code computeIfAbsent}: the difference is not the higher-order
 * function, it is the INTERFACE. {@code Predicate} and {@code Function} live in
 * {@code java/util/function/}, which {@code Candor#isJdkFunctionalSam} covers, so the lambda body's
 * {@code p.test(x)} and R183's creation-site arm both fire; {@code Comparator} does not, so nothing
 * anywhere charges it — {@code cmpParam.compare(a, b)}, invoked DIRECTLY one frame shallower, is silent
 * too. Two mechanisms, one row. This closes the first; the second is R183's stated residual (2) and is
 * pinned by {@code SamForwarderHandoffTest#theRemainingBoundaryIsTheInterfaceSetNotTheOpaqueness}.
 *
 * <p><b>NO TABLE IS WIDENED (§G).</b> R217 was filed as needing the invoker allowlist widened by hand.
 * It does not: {@code Candor#isInvokingHof} already answers "does this library higher-order function
 * invoke the functional argument it is handed", at exactly this call site, for the
 * {@code new EffImpl()} argument — {@code namedFunctionalToHof} has resolved that arm's SAM surface
 * through it since the lambda-parity fix, and it names {@code sort}, {@code computeIfAbsent} and
 * {@code removeIf}. {@code Rules#SYNC_CALLBACK_INVOKERS} and {@code Candor#FOR_EACH_FAMILY} are
 * untouched and keep answering the arg0 hand-off question they were built for.
 *
 * <p><b>A/B OVER 395 GRADLE-CACHE JARS, KEYED ON EVERY FIELD, 578,003 COMMON ROWS: ADDED 458,
 * REMOVED 0, CHANGED(every field) 963, CHANGED(inferred) 338.</b> Instrumented, because an unchanged row
 * is not evidence the new code ran: 351 events at 298 distinct sites in 60 jars. Bucketed from
 * {@code javap}, never from candor's own report — 187 {@code aload} of a parameter or local, 25 field
 * reads, 128 the return of another call, 11 mixed. The first two are recall; the third is an honest
 * disclosure that is also an IMPRECISION where the returned lambda was itself in scope
 * ({@code DaggerStreams.instancesOf(Class)} feeding {@code Stream.flatMap} is the largest cluster), and
 * that is stated rather than implied.
 */
class OpaqueCallbackToHofTest {

    /** The write is the ground truth: callbacks that really touch the filesystem when they run. */
    private static final String EFF = String.join("\n",
        "package app;",
        "import java.nio.file.*;",
        "import java.util.function.*;",
        "public class Eff implements Function<String,String>, Predicate<String>, UnaryOperator<String> {",
        "  static void touch() { try { Files.writeString(",
        "      Paths.get(System.getProperty(\"candor.r217.witness\")), \"x\",",
        "      StandardOpenOption.CREATE, StandardOpenOption.APPEND); }",
        "    catch (Exception e) { throw new RuntimeException(e); } }",
        "  public String apply(String k)  { touch(); return k; }",
        "  public boolean test(String x)  { touch(); return false; }",
        "}");

    /** THE DEFECT. Every callback here arrives OPAQUELY — as a parameter or a field — so there is no
     *  creation site in any of these methods for either existing arm to attribute anything to. No method
     *  name is a prefix of another, so a scoped policy over them cannot inherit the prefix-matching
     *  contamination the 0.35.0 panel recorded. */
    private static final String HOF = String.join("\n",
        "package app;",
        "import java.util.*;",
        "import java.util.function.*;",
        "import java.util.stream.*;",
        "public class Hof {",
        "  private Function<String,String> fnField;",
        "  public void bind(Function<String,String> f) { this.fnField = f; }",
        "  public boolean removeParam(List<String> xs, Predicate<String> p)             { return xs.removeIf(p); }",
        "  public String computeParam(Map<String,String> m, Function<String,String> f)  { return m.computeIfAbsent(\"k\", f); }",
        "  public List<String> mapField(List<String> xs)                                { return xs.stream().map(fnField).collect(Collectors.toList()); }",
        "  public List<String> filterParam(List<String> xs, Predicate<String> p)        { return xs.stream().filter(p).collect(Collectors.toList()); }",
        "  public void replaceParam(List<String> xs, UnaryOperator<String> f)           { xs.replaceAll(f); }",
        "}");

    private static final String DRIVE = String.join("\n",
        "package app;",
        "import java.util.*;",
        "public class Drive { public static void main(String[] a) {",
        "  Hof h = new Hof(); Eff e = new Eff(); h.bind(e);",
        "  h.removeParam(new ArrayList<>(List.of(\"z\")), e);",
        "  h.computeParam(new HashMap<>(), e);",
        "  h.mapField(List.of(\"z\"));",
        "  h.filterParam(List.of(\"z\"), e);",
        "  h.replaceParam(new ArrayList<>(List.of(\"z\")), e);",
        "} }");

    private static Map<String, String> fixture() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Eff.java", EFF);
        m.put("app/Hof.java", HOF);
        m.put("app/Drive.java", DRIVE);
        return m;
    }

    /** The five methods above, with NO implementor of any functional interface in scope — the shape a
     *  real scan of an application that merely CONSUMES callbacks has, and where a disclosure is the only
     *  honest answer available. */
    private static Map<String, String> hofOnly() {
        return Map.of("app/Hof.java", HOF);
    }

    private static final String[] ARMS =
            {"removeParam", "computeParam", "mapField", "filterParam", "replaceParam"};

    /** RED WITHOUT THE FIX: all five arms are ABSENT from the report on the pre-fix engine.
     *
     *  <p>§E3/§J — GROUND TRUTH EXECUTED, and stated separately from what is only analysed. All five
     *  arms are RUN and really perform five writes; nothing in this row is asserted about a program that
     *  was not executed.
     *
     *  <p>Scanned TWICE, and the pair is a control in its own right. Whether or not a class implementing
     *  {@code Predicate}/{@code Function} is in scope, the answer must be the SAME {@code Unknown}: the
     *  value is a parameter, so no candidate set pins it to {@code Eff}, and a fix that resolved it to
     *  {@code Eff} would be narrowing on a property it cannot prove. */
    @Test
    void anOpaqueCallbackAtAnInvokingHofIsDisclosedNotSilent() throws Exception {
        Path cls = compile(fixture());
        try {
            Path witness = Files.createTempFile("candor-r217", ".txt");
            Files.delete(witness);
            String saved = System.getProperty("candor.r217.witness");
            System.setProperty("candor.r217.witness", witness.toString());
            try (URLClassLoader cl = new URLClassLoader(new URL[]{cls.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                cl.loadClass("app.Drive").getMethod("main", String[].class).invoke(null, (Object) new String[0]);
            } finally {
                if (saved == null) System.clearProperty("candor.r217.witness");
                else System.setProperty("candor.r217.witness", saved);
            }
            assertEquals("xxxxx", Files.readString(witness),
                "the five arms must really perform the effect — one write each. Anything else and the "
                + "rows below are measured against a program that does not do what this row says it does");
            Files.deleteIfExists(witness);

            Map<String, EffectSet> withImpl = Candor.runScan(cls);
            for (String m : ARMS)
                assertTrue(eff(withImpl, "app.Hof." + m).contains(Effect.UNKNOWN),
                    m + " hands a caller-supplied callback to a higher-order function that really invokes "
                    + "it — the run just proved it writes a file — so it must not read silent-pure. Got "
                    + withImpl.get("app.Hof." + m));
            rm(cls.getParent());

            cls = compile(hofOnly());
            Map<String, EffectSet> alone = Candor.runScan(cls);
            for (String m : ARMS)
                assertTrue(eff(alone, "app.Hof." + m).contains(Effect.UNKNOWN),
                    m + " must give the SAME answer with no implementor in scope: the callback is a "
                    + "parameter, and nothing here pins it to any visible body. Got " + alone.get("app.Hof." + m));
        } finally { rm(cls.getParent()); }
    }

    /** THE THREE SPELLINGS OF ONE EXPRESSION, AND THE DISCLOSURE CHANNEL IS BYTE-IDENTICAL. The claim is
     *  parity, so this pins it rather than asserting it in a comment (§E2): the OPAQUE arm must produce
     *  the same {@code callback:} reason the lambda body's own unpinned-SAM read and R183's creation-site
     *  arm already produce. On the pre-fix engine the {@code Direct} rows are ABSENT and the other two
     *  are {@code Unknown} — which is the whole defect. */
    @Test
    void theThreeSpellingsAgreeOnTheOpaqueCallback() throws Exception {
        Path cls = compile(Map.of("app/Spell.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.*;",
            "public class Spell {",
            "  public boolean removeDirect(List<String> xs, Predicate<String> p) { return xs.removeIf(p); }",
            "  public boolean removeLambda(List<String> xs, Predicate<String> p) { return xs.removeIf(x -> p.test(x)); }",
            "  public boolean removeRef(List<String> xs, Predicate<String> p)    { return xs.removeIf(p::test); }",
            "  public String computeDirect(Map<String,String> m, Function<String,String> f) { return m.computeIfAbsent(\"k\", f); }",
            "  public String computeRef(Map<String,String> m, Function<String,String> f)    { return m.computeIfAbsent(\"k\", f::apply); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"removeDirect", "removeLambda", "removeRef",
                                          "computeDirect", "computeRef"})
                assertTrue(eff(r, "app.Spell." + m).contains(Effect.UNKNOWN),
                    m + " — one variable, the spelling. Got " + r.get("app.Spell." + m));
            assertEquals(why("removeRef"), why("removeDirect"),
                "the OPAQUE arm must disclose what the METHOD-REFERENCE arm already discloses, not merely "
                + "also be non-silent — a consumer reading unknownWhy sees one fact, spelled once");
            assertEquals(why("computeRef"), why("computeDirect"),
                "same, through Function.apply");
            assertEquals("[callback:java.util.function.Predicate.test]", why("removeDirect"),
                "and the reason names the interface whose SAM the JDK really invokes");
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL, AND IT IS THE POINT OF THE ALLOWLIST. Every sink here takes a genuinely
     *  {@code java.util.function}-TYPED parameter — no erasure to {@code Object} doing the work — and
     *  none of them invokes it: {@code Comparator.comparing} and the two {@code Collectors} factories
     *  STORE the extractor in the object they build, {@code Function.andThen} and {@code Predicate.and}
     *  COMPOSE. A denylist ("charge unless the sink is a known store") was already tried at this exact
     *  call site and MEASURED wrong — {@code namedFunctionalToHof}'s own history records
     *  {@code !isStoringContainerCall} firing for ANY external non-store and fabricating. So the gate is
     *  {@code isInvokingHof}, and this row is what goes RED if anyone widens it to "not obviously a
     *  store".
     *
     *  <p>DISCRIMINATING, verified by degrading: forcing the {@code isInvokingHof} gate true reddens this
     *  row. An earlier draft of it used {@code Objects.requireNonNull(f)}, {@code Optional.ofNullable(f)},
     *  {@code map.getOrDefault(k, f)}, {@code Stream.of(f)} and {@code list.add(f)} — and that draft
     *  survived the same degradation, because every one of those parameters ERASES to {@code Object}, so
     *  the interface gate excluded them and the allowlist was never consulted. It read as coverage of the
     *  allowlist and was coverage of erasure. */
    @Test
    void aNonInvokingSinkGainsNothing() throws Exception {
        Path cls = compile(Map.of("app/Store.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.*;",
            "import java.util.stream.*;",
            "public class Store {",
            "  public Comparator<String> byKey(Function<String,String> f) { return Comparator.comparing(f); }",
            "  public Collector<String,?,Map<String,List<String>>> group(Function<String,String> f) { return Collectors.groupingBy(f); }",
            "  public Collector<String,?,Map<String,String>> toMapOf(Function<String,String> k, Function<String,String> v) { return Collectors.toMap(k, v); }",
            "  public Function<String,String> chain(Function<String,String> f, Function<String,String> g) { return f.andThen(g); }",
            "  public Predicate<String> both(Predicate<String> p, Predicate<String> q) { return p.and(q); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"byKey", "group", "toMapOf", "chain", "both"})
                assertFalse(eff(r, "app.Store." + m).contains(Effect.UNKNOWN),
                    m + " hands the callback to a sink that STORES or COMPOSES it and never invokes it — "
                    + "charging it is a FABRICATION, and it is the exact fabrication this site has already "
                    + "shipped once. Got " + r.get("app.Store." + m));
        } finally { rm(cls.getParent()); }
    }

    /** A LAMBDA AND A METHOD REFERENCE AT THE SAME HIGHER-ORDER FUNCTION ARE ALREADY ANSWERED AT THEIR
     *  CREATION SITE, and this fix must not answer them a second time. A PURE lambda body and a reference
     *  to a concrete pure method stay pure; the effectful lambda beside them keeps the precise {@code Fs}
     *  it has always had, rather than degrading to a disclosure.
     *
     *  <p>DISCRIMINATING: deleting the {@code fromIndy} gate reddens the two pure rows. */
    @Test
    void aLambdaOrMethodReferenceAtTheSameHofIsUnchanged() throws Exception {
        Path cls = compile(Map.of("app/Inline.java", String.join("\n",
            "package app;",
            "import java.nio.file.*;",
            "import java.util.*;",
            "public class Inline {",
            "  public boolean pureLambda(List<String> xs) { return xs.removeIf(x -> x.isEmpty()); }",
            "  public boolean pureRef(List<String> xs)    { return xs.removeIf(String::isEmpty); }",
            "  public boolean effLambda(List<String> xs)  { return xs.removeIf(x -> { write(x); return true; }); }",
            "  static void write(String x) { try { Files.writeString(Paths.get(x), \"y\"); } catch (Exception e) {} }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"pureLambda", "pureRef"})
                assertFalse(eff(r, "app.Inline." + m).contains(Effect.UNKNOWN),
                    m + " has a creation site right here and its body is already edged there — a second, "
                    + "blanket Unknown for the same value is an over-charge. Got " + r.get("app.Inline." + m));
            assertTrue(eff(r, "app.Inline.effLambda").contains(Effect.FS),
                "and the effectful twin keeps the PRECISE effect rather than being hedged into Unknown: "
                + r.get("app.Inline.effLambda"));
            assertFalse(eff(r, "app.Inline.effLambda").contains(Effect.UNKNOWN),
                "…precise, not precise-plus-hedged: " + r.get("app.Inline.effLambda"));
        } finally { rm(cls.getParent()); }
    }

    /** AN ORDINARY VALUE THAT MERELY SITS AT A HIGHER-ORDER CALL SITE IS NOT A CALLBACK. {@code merge}
     *  and {@code computeIfAbsent} are both on the invoker allowlist and both take a plain value beside
     *  the callback.
     *
     *  <p>PASSES IN BOTH ARMS BY CONSTRUCTION, AND IS NOT CLAIMED TO DISCRIMINATE THE FIX. Measured by
     *  degrading: dropping the {@code isFunctionalIface} gate does NOT redden it, because those
     *  parameters erase to {@code Object} and {@code samNameOf} has no SAM for {@code Object} — the
     *  erasure excludes them, not the gate. It is kept because it is the row that would catch a future
     *  change keying on something other than the parameter's declared type. The gate's real
     *  discriminator is {@code SamForwarderHandoffTest#theRemainingBoundaryIsTheInterfaceSetNotTheOpaqueness},
     *  which goes red when the interface set widens. */
    @Test
    void aNonFunctionalArgumentAtAnInvokingHofGainsNothing() throws Exception {
        Path cls = compile(Map.of("app/Plain.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "public class Plain {",
            "  public String mergeValue(Map<String,String> m, String k, String v) {",
            "    return m.merge(k, v, (a, b) -> a); }",
            "  public String computeKey(Map<String,String> m, String k) {",
            "    return m.computeIfAbsent(k, x -> x); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"mergeValue", "computeKey"})
                assertFalse(eff(r, "app.Plain." + m).contains(Effect.UNKNOWN),
                    m + " passes an opaque STRING to an invoking higher-order function; a string is not a "
                    + "callback and charging it is a fabrication. Got " + r.get("app.Plain." + m));
        } finally { rm(cls.getParent()); }
    }

    /** ONE FACT, SPELLED ONCE. {@code list.forEach(opaqueConsumer)} was ALREADY disclosed, by
     *  {@code opaqueTaskHandoff}, which runs first in the same per-instruction block and owns arg0 of a
     *  hand-off verb. This fix must not add a second reason saying the same thing to every {@code forEach}
     *  in the corpus. The {@code LongStream} row beside it is the control that keeps the guard honest:
     *  {@code LongConsumer} is NOT in {@code Rules#TASK_ARG_PREFIXES}, so that path never fired there and
     *  this one must.
     *
     *  <p>DISCRIMINATING in BOTH directions, verified by degrading: deleting the arg0 guard reddens the
     *  {@code forEach} row, and widening it from {@code i == 0} to ANY argument reddens the
     *  {@code ifPresentOrElse} row. The first draft claimed the {@code LongStream} row covered that second
     *  direction and it does not — {@code LongConsumer} is not in {@code TASK_ARG_PREFIXES}, so the guard
     *  never fires there whatever its index test says, and the degradation came back green. */
    @Test
    void theForEachHandoffKeepsItsSingleReasonAndThePrimitiveOneIsNotLost() throws Exception {
        Path cls = compile(Map.of("app/Widget.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.*;",
            "import java.util.stream.*;",
            "public class Widget {",
            "  public void each(List<String> xs, Consumer<String> c)      { xs.forEach(c); }",
            "  public void eachLong(LongStream s, LongConsumer c)         { s.forEach(c); }",
            "  public void orElse(Optional<String> o, Consumer<String> c, Runnable r) { o.ifPresentOrElse(c, r); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Widget.each").contains(Effect.UNKNOWN), "forEach was already disclosed");
            assertEquals("[task-handoff:java.util.List.forEach]", whyOf("app.Widget.each"),
                "opaqueTaskHandoff already owns arg0 of a hand-off verb and ran first — a second reason "
                + "here is the same fact spelled twice, on every forEach in every report");
            assertTrue(eff(r, "app.Widget.eachLong").contains(Effect.UNKNOWN),
                "…and LongConsumer is not in TASK_ARG_PREFIXES, so that path never fired for the "
                + "primitive stream family and this one must. Got " + r.get("app.Widget.eachLong"));
            assertEquals("[callback:java.util.function.LongConsumer.accept]", whyOf("app.Widget.eachLong"),
                "with the interface the JDK really invokes named");
            assertEquals("[callback:java.lang.Runnable.run, task-handoff:java.util.Optional.ifPresentOrElse]",
                whyOf("app.Widget.orElse"),
                "and the guard is `i == 0` rather than `any argument`, because `opaqueTaskHandoff` reads "
                + "arg0 ONLY: ifPresentOrElse takes a SECOND opaque callback that path has never seen, so "
                + "deferring to it wholesale would drop the Runnable arm. Two reasons here is two facts, "
                + "not one fact twice");
        } finally { rm(cls.getParent()); }
    }

    /** A PROJECT-OWNED HIGHER-ORDER FUNCTION IS ANALYSED, NOT GUESSED AT. {@code Local.map} is in scope,
     *  so its body carries whatever it really does with the callback; disclosing at the CALL site as well
     *  would hedge a question the scan can answer exactly. The name is deliberately one
     *  {@code isInvokingHof} lists.
     *
     *  <p>DISCRIMINATING: dropping the enclosing {@code !projectClasses.contains(min.owner)} gate
     *  reddens this row. */
    @Test
    void aProjectOwnedHofIsAnalysedNotDisclosed() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Local.java", String.join("\n",
            "package app;",
            "import java.util.function.*;",
            "public class Local {",
            "  public String map(String x, Function<String,String> f) { return x; }",
            "}"));
        m.put("app/Caller.java", String.join("\n",
            "package app;",
            "import java.util.function.*;",
            "public class Caller {",
            "  public String go(Function<String,String> f) { return new Local().map(\"a\", f); }",
            "}"));
        Path cls = compile(m);
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "app.Caller.go").contains(Effect.UNKNOWN),
                "Local.map is in scope and never invokes the callback — the scan can answer this exactly, "
                + "and hedging it here would charge a project HOF for the sin of being named `map`. Got "
                + r.get("app.Caller.go"));
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** The rendered {@code unknownWhy} strings recorded for {@code app.Spell.<m>} by the scan just run. */
    private static String why(String m) { return whyOf("app.Spell." + m); }

    private static String whyOf(String fn) {
        TreeSet<UnknownReason> s = AnalysisState.ctx().unknownWhy.get(fn);
        return s == null ? "<none>" : s.toString();
    }
}
