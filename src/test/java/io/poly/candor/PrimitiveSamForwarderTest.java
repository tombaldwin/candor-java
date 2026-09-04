package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
 * SOUNDNESS R191 — A METHOD REFERENCE TO THE SAM OF AN INTERFACE THE HAND-WRITTEN {@code SAM_OF} TABLE
 * DID NOT LIST — WHICH IS EVERY PRIMITIVE-SPECIALISED {@code java.util.function} INTERFACE — WAS SILENT.
 *
 * <p><b>THE DEFECT.</b> {@code isups.forEach(IntSupplier::getAsInt)} and
 * {@code bsups.forEach(BooleanSupplier::getAsBoolean)} were ABSENT from {@code functions[]} entirely,
 * while the lambda twin {@code isups.forEach(s -> s.getAsInt())} discloses {@code Unknown} with
 * {@code callback:java.util.function.IntSupplier.getAsInt}. One variable: the spelling. Measured on TWO
 * PUBLISHED 0.35.0 ARTIFACTS — the fat jar and the native binary — with identical cells, and with the
 * ground truth EXECUTED (all three silent spellings really write the probe file):
 *
 * <pre>
 *   policy                                       PUB 0.35.0 jar   PUB 0.35.0 native   this fix
 *   deny Unknown app.Widget.viaIntSupplier             0                 0                1
 *   deny Unknown app.Widget.viaBoolSupplier            0                 0                1
 *   deny Unknown app.Widget.viaIterable                0                 0                1  &lt;- §A.2
 *   deny Unknown app.Widget.lambdaIntArm               1                 1                1  &lt;- the twin
 *   deny Unknown app.Widget.viaObjSupplier             1                 1                1  &lt;- listed
 *   deny Unknown app.Widget.printAll / trimAll         0                 0                0  &lt;- concrete
 *   deny Unknown app.Widget.lenAll                     0                 0                0  &lt;- 3 abstracts
 *   deny Unknown (blanket)                             1                 1                1  &lt;- INCIDENTAL
 * </pre>
 *
 * <p>{@code pure &lt;fn&gt;} is 0 on every arm for every spelling — {@code pure} does not bind
 * {@code Unknown} by design — and scoped {@code deny Fs} is 0 on every arm INCLUDING the lambda twin,
 * because the effect these methods carry is {@code Unknown}, not {@code Fs}. Neither cell discriminates
 * anything here; scoped {@code deny Unknown} is the one that does, and it is what these rows assert.
 *
 * <p><b>THE MECHANISM, AND IT IS A SAFETY SENTENCE THAT WAS WRONG ABOUT ITS OWN CONSUMER (§E2/§K).</b>
 * {@code Candor.SAM_OF}'s doc claimed a {@code java/util/function/} interface it does not list "falls
 * through to the CONSERVATIVE branch below (charge the whole surface) rather than to silence". That is
 * true of {@link Candor#handoffInvoked} — its null makes {@link Candor#depFnsInvokedByHandoff} charge the
 * type's whole reported surface — and FALSE of {@link Candor#samForwarderTarget}, added later by R179,
 * where the null leaves {@code opaqueTaskHandoff}'s {@code Unknown} suppressed, because the caller's only
 * other route to a disclosure is {@code !task.fromIndy} and an indy always sets that. Two consumers, one
 * table, opposite fail directions. The comment was written by the change that needed it to be true.
 *
 * <p><b>THE FIX IS A DENYLIST, NOT MORE ENTRIES.</b> Adding {@code IntSupplier} and its siblings to the
 * table is the same allowlist one row further along, and would fail silent for the next interface nobody
 * listed — which is precisely how this row exists (R179 chose the table for a documented reason, and the
 * reason held for the case it was tested on). {@link Candor#samNameOf} instead asks an index DERIVED FROM
 * THE BUILD JDK (§G): every JDK interface with exactly one abstract method, computed over the interface
 * and its super-interfaces, ignoring statics, ignoring the {@code Object} methods JLS 9.8 permits
 * ({@code Comparator} declares {@code equals} abstract), and subtracting the signatures a {@code default}
 * gives a body to. 732 interfaces, ~10KB gzipped.
 */
class PrimitiveSamForwarderTest {

    private static final String STORE = String.join("\n",
        "package app;",
        "import java.nio.file.*;",
        "public class Store {",
        "  public int bump() { try { Files.writeString(",
        "      Paths.get(System.getProperty(\"candor.r191.witness\")), \"x\",",
        "      StandardOpenOption.CREATE, StandardOpenOption.APPEND); }",
        "    catch (Exception e) { throw new RuntimeException(e); }",
        "    return 1; }",
        "  public boolean flag() { bump(); return true; }",
        "  public String name() { bump(); return \"n\"; }",
        "}");

    /** Named so that NO NAME IS A PREFIX OF ANOTHER — the 0.35.0 panel recorded a cell contaminated by
     *  scope prefix-matching, and every assertion below is made through a SCOPED policy's own key space. */
    private static final String WIDGET = String.join("\n",
        "package app;",
        "import java.util.*;",
        "import java.util.function.*;",
        "public class Widget {",
        "  private final List<IntSupplier> isups = new ArrayList<>();",
        "  private final List<BooleanSupplier> bsups = new ArrayList<>();",
        "  private final List<Supplier<String>> gsups = new ArrayList<>();",
        "  private final List<String> texts = new ArrayList<>();",
        "  private final List<CharSequence> seqs = new ArrayList<>();",
        "  private final List<Iterable<String>> iters = new ArrayList<>();",
        "  public void install(Store s) {",
        "    isups.add(s::bump); bsups.add(s::flag); gsups.add(s::name);",
        "    texts.add(\"hello\"); seqs.add(\"hello\");",
        "    iters.add(() -> { s.bump(); return java.util.List.<String>of().iterator(); }); }",
        "  public void viaIntSupplier()  { isups.forEach(IntSupplier::getAsInt); }",
        "  public void viaBoolSupplier() { bsups.forEach(BooleanSupplier::getAsBoolean); }",
        "  public void viaIterable()     { iters.forEach(Iterable::iterator); }",
        "  public void lambdaIntArm()    { isups.forEach(s -> s.getAsInt()); }",
        "  public void viaObjSupplier()  { gsups.forEach(Supplier::get); }",
        "  public void printAll()        { texts.forEach(System.out::println); }",
        "  public void trimAll()         { texts.forEach(String::trim); }",
        "  public void lenAll()          { seqs.forEach(CharSequence::length); }",
        "}");

    private static final String MAIN = String.join("\n",
        "package app;",
        "public class Main { public static void main(String[] a) {",
        "  Widget w = new Widget(); w.install(new Store());",
        "  w.viaIntSupplier(); w.viaBoolSupplier(); w.viaIterable();",
        "} }");

    private static Map<String, String> fixture() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Store.java", STORE);
        m.put("app/Widget.java", WIDGET);
        m.put("app/Main.java", MAIN);
        return m;
    }

    /** RED without the fix: both methods are ABSENT from the report entirely, so
     *  {@code deny Unknown app.Widget.viaIntSupplier} exits 0 over a method that really writes a file. */
    @Test
    void aPrimitiveSpecialisedSamReferenceIsDisclosedNotSilent() throws Exception {
        Path cls = compile(fixture());
        try {
            // §E3 — GROUND TRUTH FIRST. Both arms are RUN and each really performs the write; without
            // this the absence rows below could not tell a correct engine from a broken one, because an
            // omitted pure function and an omitted effectful one are the same bytes.
            Path witness = Files.createTempFile("candor-r191", ".txt");
            Files.delete(witness);
            String saved = System.getProperty("candor.r191.witness");
            System.setProperty("candor.r191.witness", witness.toString());
            try (URLClassLoader cl = new URLClassLoader(new URL[]{cls.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                cl.loadClass("app.Main").getMethod("main", String[].class).invoke(null, (Object) new String[0]);
            } finally {
                if (saved == null) System.clearProperty("candor.r191.witness");
                else System.setProperty("candor.r191.witness", saved);
            }
            assertEquals("xxx", Files.readString(witness),
                "all three method-reference spellings must really perform the effect — three writes, one "
                + "per arm. Anything else and the engine rows below are measured against the wrong "
                + "program");
            Files.deleteIfExists(witness);

            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Widget.viaIntSupplier").contains(Effect.UNKNOWN),
                "IntSupplier::getAsInt names an ABSTRACT method — the body that runs belongs to whatever "
                + "receiver forEach supplies, so this must disclose, never read pure. Got "
                + r.get("app.Widget.viaIntSupplier"));
            assertTrue(why("viaIntSupplier").contains("callback:java.util.function.IntSupplier.getAsInt"),
                "…with the SAME reason the lambda twin produces, so the two spellings are identical in "
                + "the disclosure channel and not merely both non-silent. Got " + why("viaIntSupplier"));
            assertTrue(eff(r, "app.Widget.viaBoolSupplier").contains(Effect.UNKNOWN),
                "so must the BooleanSupplier arm — the point of the index is that it is not a list of the "
                + "interfaces someone remembered. Got " + r.get("app.Widget.viaBoolSupplier"));
            assertTrue(why("viaBoolSupplier").contains("callback:java.util.function.BooleanSupplier.getAsBoolean"),
                "Got " + why("viaBoolSupplier"));
            // §A.2 — THE SIBLING THIS ROW WAS NOT HANDED. The row is written about
            // `java.util.function`, and a fix scoped to that package would pass every assertion above
            // while staying silent one package over. `Iterable::iterator` is the shape the 395-jar
            // corpus actually contains (guava, ant, spring-data-commons), and it is silent on the
            // published 0.35.0 by the same mechanism: measured exit 0 there, exit 1 here.
            assertTrue(eff(r, "app.Widget.viaIterable").contains(Effect.UNKNOWN),
                "Iterable is a functional interface outside java.util.function — the rule is 'the single "
                + "abstract method of a functional interface', not 'a package we listed'. Got "
                + r.get("app.Widget.viaIterable"));
            assertTrue(why("viaIterable").contains("callback:java.lang.Iterable.iterator"),
                "Got " + why("viaIterable"));
        } finally { rm(cls.getParent()); }
    }

    /** THE ONE-VARIABLE CONTROLS. The lambda twin is what makes "the spelling is the only difference" a
     *  measurement; {@code Supplier::get} is the sibling the 2026-09-04 re-measurement confirmed was
     *  ALREADY disclosed on 0.35.0 (Supplier is in the hand-written table), and it must not move. Both
     *  pass in BOTH arms by construction and neither is claimed to discriminate this fix. */
    @Test
    void theLambdaTwinAndTheAlreadyListedSiblingAreUnchanged() throws Exception {
        Path cls = compile(fixture());
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Widget.lambdaIntArm").contains(Effect.UNKNOWN),
                "the lambda spelling disclosed before this fix and must still: " + r.get("app.Widget.lambdaIntArm"));
            assertTrue(eff(r, "app.Widget.viaObjSupplier").contains(Effect.UNKNOWN),
                "Supplier::get was already disclosed on the published 0.35.0 and must stay identical: "
                + r.get("app.Widget.viaObjSupplier"));
            assertTrue(why("viaObjSupplier").contains("callback:java.util.function.Supplier.get"),
                "…including its reason string: " + why("viaObjSupplier"));
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROLS, and the rows that discriminate this fix from the WIDER one it stops
     *  short of. {@code System.out::println} and {@code String::trim} name CONCRETE bodies; the classifier's
     *  answer for them is the authority and nothing here may charge {@code Unknown} over it.
     *  {@code CharSequence::length} names an ABSTRACT method — so a fix keyed on "the target is
     *  ACC_ABSTRACT" would turn this row red — but {@code CharSequence} has THREE abstract methods, is not
     *  a functional interface, and its receiver is a {@code String} in essentially all real code.
     *  Fabrication is the direction with no gate behind it, so the rule stops at the SAM. */
    @Test
    void concreteAndMultiAbstractJdkReferencesStayPure() throws Exception {
        Path cls = compile(fixture());
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"printAll", "trimAll", "lenAll"})
                assertFalse(eff(r, "app.Widget." + m).contains(Effect.UNKNOWN),
                    m + " names either a concrete JDK body or a non-functional interface — disclosing "
                    + "Unknown here would be a fabrication on provably pure code. Got "
                    + r.get("app.Widget." + m));
        } finally { rm(cls.getParent()); }
    }

    /** THE INDEX IS THE FIX, SO ITS ABSENCE MUST BE LOUD. {@code JdkSams} degrades to an empty map when the
     *  generated resource is not on the classpath, and that degradation is exactly the pre-R191 behaviour —
     *  silent, and indistinguishable from a correct engine over pure code. This row is what stops a build
     *  that forgot {@code generateJdkSams} (or a native image built without the {@code IncludeResources}
     *  line) from passing as fixed. It also pins the derivation's two edges: an interface with more than
     *  one abstract method has NO sam, and {@code Comparator} — which declares {@code equals(Object)}
     *  abstract beside {@code compare} — still does. */
    @Test
    void theJdkSamIndexIsBundledAndAnswersTheInterfacesThisRowIsAbout() {
        assertNotNull(Candor.class.getResourceAsStream("/candor/jdk-sams.idx.gz"),
            "the build-time JDK SAM index is missing from the classpath — samNameOf then answers from "
            + "SAM_OF alone, which is the allowlist this row was filed against");
        assertEquals("getAsInt", Candor.samNameOf("java/util/function/IntSupplier"));
        assertEquals("getAsBoolean", Candor.samNameOf("java/util/function/BooleanSupplier"));
        assertEquals("getAsLong", Candor.samNameOf("java/util/function/LongSupplier"));
        assertEquals("applyAsInt", Candor.samNameOf("java/util/function/ToIntFunction"));
        assertEquals("apply", Candor.samNameOf("java/util/function/UnaryOperator"),
            "UnaryOperator declares NO abstract method of its own — its SAM is inherited from Function, "
            + "so the derivation has to walk super-interfaces or it fails silent on exactly this shape");
        assertEquals("compare", Candor.samNameOf("java/util/Comparator"),
            "Comparator declares equals(Object) abstract beside compare; a derivation that counts it "
            + "would find two abstracts and drop Comparator::compare back into silence");
        assertNull(Candor.samNameOf("java/lang/CharSequence"),
            "three abstract methods — not a functional interface, and the reason lenAll stays pure");
        assertNull(Candor.samNameOf("java/util/List"), "an ordinary interface has no SAM");
        assertNull(Candor.samNameOf("java/io/PrintStream"), "a CLASS is not a functional interface");
    }

    /** §9 — THE OTHER CONSUMER OF THE SAME TABLE, DELIBERATELY NOT WIDENED. {@link Candor#handoffInvoked}
     *  reads {@code SAM_OF} to decide which MEMBERS of a handed-off dependency type a runtime can invoke,
     *  and its null means "charge the type's whole surface". Pointing it at {@link Candor#samNameOf} would
     *  narrow that from the whole surface to one method — a precision gain in the UNDER-report direction,
     *  which is a separate question with the opposite fail direction from this row. Passes in BOTH arms;
     *  it is here so that a later widening of this fix has to argue with a test rather than with a
     *  comment. */
    @Test
    void theWholeSurfaceHandoffConsumerIsNotWidenedByThisRow() {
        assertNull(Candor.handoffInvoked("java/util/function/IntSupplier"),
            "an interface absent from SAM_OF must still yield null HERE, so depFnsInvokedByHandoff keeps "
            + "falling back to the whole reported surface — the conservative direction, unchanged");
        assertEquals(java.util.Set.of("<init>", "run"), Candor.handoffInvoked("java/lang/Runnable"),
            "…and a listed one must still yield its SAM plus the constructor");
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
