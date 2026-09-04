package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

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

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R183 — A METHOD REFERENCE HANDED TO A HIGHER-ORDER FUNCTION THE INVOKER ALLOWLIST DOES NOT
 * NAME READ SILENT-PURE, WHILE THE LAMBDA SPELLING OF THE SAME EXPRESSION DISCLOSED.
 *
 * <p><b>THE DEFECT.</b> {@code Optional.ofNullable(sup).map(Supplier::get)} is ABSENT from
 * {@code functions[]}; {@code map(s -> s.get())} is {@code ['Unknown']}. One variable: the spelling.
 * {@code deny Unknown app.…viaMethodRef} exits 0 "no violations" over a method that really performs the
 * effect, against exit 1 on the lambda twin. Same for {@code stream().map}, {@code filter},
 * {@code collect} and {@code anyMatch} — every higher-order function outside
 * {@code Rules#SYNC_CALLBACK_INVOKERS} / {@code Candor#FOR_EACH_FAMILY}, which is nearly all of them.
 *
 * <p><b>THE ROW ASKED "WHICH HOFS INVOKE THEIR CALLBACK", AND THAT QUESTION DOES NOT HAVE TO BE
 * ANSWERED.</b> R179 fixed the same false premise at the HAND-OFF site, so it reached only the invoker
 * allowlist, and R183 was filed as "now widen the allowlist" — the fabrication direction, resting on a
 * distinction (synchronous, in the caller's frame, versus stored/deferred/elsewhere) that no JDK
 * signature, {@code @FunctionalInterface} marker or {@code default}-with-a-body carries. Nothing at a
 * CREATION site needs it, because <b>the LAMBDA arm has never known what the sink does either</b>:
 * {@code Candor#handleInvokeDynamic} edges a lambda at its creation site unless it ESCAPES UNINVOKED or
 * feeds a curated deferred container, and that one flag is the engine's whole settled stance on lazy and
 * stored sinks. Measured on the pre-fix jar, and this is why {@code Stream.map} is not the hazard it
 * looks like: {@code list.stream().map(s -> s.get())} with NO terminal operation is ALREADY
 * {@code Unknown} there. The method-reference spelling was simply never asking the question.
 *
 * <p><b>SO NO TABLE IS WIDENED.</b> {@code SYNC_CALLBACK_INVOKERS} and {@code FOR_EACH_FAMILY} are
 * untouched and remain the authority for the different question they answer — an OPAQUE callback (a
 * field, a param) at a site with no indy to attribute to. That silence is still open; it is pinned by
 * {@code SamForwarderHandoffTest#theRemainingBoundaryIsTheOPAQUECallbackNotTheSpelling}, which replaced
 * the boundary row this fix made obsolete.
 *
 * <p><b>THE PREDICATE IS BORROWED, NOT INVENTED (§G).</b> The gate is {@code isJdkFunctionalSam} — the
 * predicate that already decides the lambda arm at {@code handleMethodInsn}'s unpinned-SAM branch — and
 * the CHA fan-out is consulted first, exactly as it is there and in the project-owner branch of
 * {@code handleInvokeDynamic}. Keying on {@code samNameOf} (R191's 732-interface JDK index) was tried
 * and MEASURED first, and rejected: it charges {@code Unknown} over
 * {@code stream().map(Iterable::iterator)}, {@code map(Principal::getName)} and
 * {@code sorted(c::compare)} where {@code x -> x.iterator()} and {@code p -> p.getName()} stay pure —
 * a NEW fabrication on the front door of {@code Stream}, which is the outcome this row must not have.
 */
class HofSpellingParityTest {

    /** The write is the ground truth: a supplier that really touches the filesystem when it runs. */
    private static final String SUP = String.join("\n",
        "package app;",
        "import java.nio.file.*;",
        "import java.util.function.Supplier;",
        "public class Sup implements Supplier<String> {",
        "  public String get() { try { Files.writeString(",
        "      Paths.get(System.getProperty(\"candor.r183.witness\")), \"x\",",
        "      StandardOpenOption.CREATE, StandardOpenOption.APPEND); }",
        "    catch (Exception e) { throw new RuntimeException(e); } return \"x\"; }",
        "}");

    /** THE DEFECT AND ITS ONE-VARIABLE TWIN, five higher-order functions wide. No method name here is a
     *  prefix of another — a scoped policy over these would otherwise inherit the prefix-matching
     *  contamination the 0.35.0 panel recorded. The supplier arrives as a PARAMETER, so no arm can be
     *  resolved by provenance and the only question is the spelling.
     *
     *  <p>Scanned TWICE, and the two scans are not interchangeable. WITH {@code Sup} in scope — the tree
     *  the driver executes — CHA resolves both arms to a real body and the effect is the precise
     *  {@code Fs} the run really performed. WITHOUT it ({@link #hofOnly()}), no body is reachable and the
     *  honest answer is {@code Unknown}. The pre-fix jar is ABSENT in both, which is the defect. */
    private static final String HOF = String.join("\n",
        "package app;",
        "import java.util.*;",
        "import java.util.function.*;",
        "import java.util.stream.*;",
        "public class Hof {",
        "  public String optMapRef(Supplier<String> s)  { return Optional.of(s).map(Supplier::get).orElse(null); }",
        "  public String optMapLam(Supplier<String> s)  { return Optional.of(s).map(x -> x.get()).orElse(null); }",
        "  public List<String> collectRef(List<Supplier<String>> xs) { return xs.stream().map(Supplier::get).collect(Collectors.toList()); }",
        "  public List<String> collectLam(List<Supplier<String>> xs) { return xs.stream().map(x -> x.get()).collect(Collectors.toList()); }",
        "  public boolean anyRef(List<Supplier<String>> xs) { return xs.stream().map(Supplier::get).anyMatch(Objects::nonNull); }",
        "  public boolean anyLam(List<Supplier<String>> xs) { return xs.stream().map(x -> x.get()).anyMatch(Objects::nonNull); }",
        "  public Stream<String> lazyRef(List<Supplier<String>> xs) { return xs.stream().map(Supplier::get); }",
        "  public Stream<String> lazyLam(List<Supplier<String>> xs) { return xs.stream().map(x -> x.get()); }",
        "  public String computeRef(Map<String,Supplier<String>> m, String k) { return m.get(k) == null ? null : Optional.of(m.get(k)).map(Supplier::get).orElse(null); }",
        "}");

    private static final String DRIVE = String.join("\n",
        "package app;",
        "import java.util.*;",
        "public class Drive { public static void main(String[] a) {",
        "  Hof h = new Hof(); Sup s = new Sup();",
        "  h.optMapRef(s); h.optMapLam(s);",
        "  h.collectRef(List.of(s)); h.collectLam(List.of(s));",
        "  h.anyRef(List.of(s)); h.anyLam(List.of(s));",
        "} }");

    private static Map<String, String> fixture() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Sup.java", SUP);
        m.put("app/Hof.java", HOF);
        m.put("app/Drive.java", DRIVE);
        return m;
    }

    /** The same higher-order functions with NO implementor of {@code Supplier} in scope, so CHA is empty
     *  and the only honest answer is a disclosure. This is the shape a real scan of an application that
     *  merely CONSUMES callbacks has, and it is where the silence was. */
    private static Map<String, String> hofOnly() {
        return Map.of("app/Hof.java", HOF);
    }

    /** RED WITHOUT THE FIX on {@code optMapRef}, {@code collectRef} and {@code anyRef}: each is ABSENT
     *  from the report entirely on the pre-fix jar.
     *
     *  <p>§E3/§J — GROUND TRUTH EXECUTED, and the executed set is stated separately from the inferred one.
     *  The six driven arms are RUN and really perform six writes. The LAZY pair is deliberately NOT driven
     *  and is NOT claimed to be executed ground truth: {@code stream().map(…)} with no terminal operation
     *  performs nothing, in either spelling, and it is charged here for PARITY with the lambda arm that
     *  already charged it — see {@code theTwoSpellingsAgreeOnEveryShape}. */
    @Test
    void aMethodReferenceOutsideTheInvokerAllowlistIsDisclosedNotSilent() throws Exception {
        Path cls = compile(fixture());
        try {
            Path witness = Files.createTempFile("candor-r183", ".txt");
            Files.delete(witness);
            String saved = System.getProperty("candor.r183.witness");
            System.setProperty("candor.r183.witness", witness.toString());
            try (URLClassLoader cl = new URLClassLoader(new URL[]{cls.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                cl.loadClass("app.Drive").getMethod("main", String[].class).invoke(null, (Object) new String[0]);
            } finally {
                if (saved == null) System.clearProperty("candor.r183.witness");
                else System.setProperty("candor.r183.witness", saved);
            }
            assertEquals("xxxxxx", Files.readString(witness),
                "the six EAGER arms must really perform the effect — one write each, three method-reference "
                + "spellings and their three lambda twins. Anything else and the rows below are measured "
                + "against a program that does not do what this row says it does");
            Files.deleteIfExists(witness);

            // ARM 1 — the tree that was just RUN. `Sup` is in scope, so the three eager reference arms
            // must carry the PRECISE Fs the run performed. On the pre-fix jar all three are ABSENT.
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"optMapRef", "collectRef", "anyRef"})
                assertTrue(eff(r, "app.Hof." + m).contains(Effect.FS),
                    m + " really wrote the witness file a moment ago through a method reference, and it "
                    + "resolves to app.Sup.get — it must carry that Fs, not read pure. Got "
                    + r.get("app.Hof." + m));
        } finally { rm(cls.getParent()); }

        // ARM 2 — the SAME source with no implementor in scope, the shape a consuming application has.
        // Nothing is reachable, so the honest answer is a disclosure rather than a precise effect.
        Path bare = compile(hofOnly());
        try {
            Map<String, EffectSet> r = Candor.runScan(bare);
            for (String m : new String[] {"optMapRef", "collectRef", "anyRef", "lazyRef", "computeRef"})
                assertTrue(eff(r, "app.Hof." + m).contains(Effect.UNKNOWN),
                    m + " hands a bodiless SAM reference to a higher-order function the invoker allowlist "
                    + "does not name, with no body reachable — it must disclose exactly as its lambda twin "
                    + "does, never read pure. Got " + r.get("app.Hof." + m));
        } finally { rm(bare.getParent()); }
    }

    /** THE CLAIM THIS FIX IS MADE ON, PINNED RATHER THAN ASSERTED (§E2). The comment at the fix site says
     *  the new disclosure fires exactly where the LAMBDA spelling of the same expression already fires.
     *  Here that is a measurement: four pairs, one expression each, spelled both ways, and the two
     *  {@code inferred} sets must be EQUAL. If the claim were ever false — a HOF where the reference arm
     *  charges and the lambda arm does not — this goes red instead of the comment quietly lying.
     *
     *  <p>The LAZY pair is the one that matters most, and it is why {@code Stream.map} is not the hazard
     *  the row feared: {@code map(x -> x.get())} with no terminal operation is {@code Unknown} on the
     *  PRE-fix jar, so the reference arm joining it changes nothing about what the engine claims, only
     *  about which spellings claim it. */
    @Test
    void theTwoSpellingsAgreeOnEveryShape() throws Exception {
        Path cls = compile(hofOnly());
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String[] pair : new String[][] {
                    {"optMapRef", "optMapLam"}, {"collectRef", "collectLam"},
                    {"anyRef", "anyLam"}, {"lazyRef", "lazyLam"}})
                assertEquals(eff(r, "app.Hof." + pair[1]), eff(r, "app.Hof." + pair[0]),
                    pair[0] + " and " + pair[1] + " are ONE expression spelled two ways. The fix's whole "
                    + "over-charge bound is that they agree — a reference arm that charges where its lambda "
                    + "twin does not is a NEW fabrication, which is the outcome this row must not have");
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL FOR THE DEFERRED DIRECTION, and it is a control on BOTH spellings, so it
     *  cannot be satisfied by a carve-out that only exempts references. A callback that ESCAPES UNINVOKED
     *  — stored into a field, returned, added to a collection — must not be charged at the creation site
     *  in EITHER spelling: it does not run here, and it discloses later at the unpinned SAM read
     *  ({@code readIt} is that row, and it is charged, so this is a relocation of the disclosure and not
     *  a loss of it).
     *
     *  <p>Passes in BOTH arms by construction — {@code lambdaEscapesUninvoked} predates this fix and is
     *  reused unchanged. It is here because it is exactly the property a wrong version of this fix would
     *  break. */
    @Test
    void aReferenceThatEscapesUninvokedIsNotChargedAtItsCreationSite() throws Exception {
        Path cls = compile(Map.of("app/Escape.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.Supplier;",
            "public class Escape {",
            "  private Supplier<String> field;",
            "  private final List<Supplier<String>> queue = new ArrayList<>();",
            "  public void storeRef(Supplier<String> s) { this.field = s::get; }",
            "  public void storeLam(Supplier<String> s) { this.field = () -> s.get(); }",
            "  public Supplier<String> giveRef(Supplier<String> s) { return s::get; }",
            "  public Supplier<String> giveLam(Supplier<String> s) { return () -> s.get(); }",
            "  public void queueRef(Supplier<String> s) { queue.add(s::get); }",
            "  public void queueLam(Supplier<String> s) { queue.add(() -> s.get()); }",
            "  public String readIt() { return field.get(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"storeRef", "storeLam", "giveRef", "giveLam", "queueRef", "queueLam"})
                assertFalse(eff(r, "app.Escape." + m).contains(Effect.UNKNOWN),
                    m + " STOWS the callback rather than running it — charging the creation site would "
                    + "misattribute the effect here and, through the <clinit>/<init> amplifier, smear it "
                    + "over the class. Got " + r.get("app.Escape." + m));
            assertTrue(eff(r, "app.Escape.readIt").contains(Effect.UNKNOWN),
                "…and the disclosure is RELOCATED, not lost: the later unpinned SAM read carries it. "
                + "Without this row the six above could be satisfied by simply losing the effect. Got "
                + r.get("app.Escape.readIt"));
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL FOR THE PREDICATE, and the row that discriminates this fix from the wrong
     *  one. Four references that name no unpinned JDK functional SAM must stay pure: two CONCRETE bodies
     *  ({@code String::trim}, {@code Objects::nonNull} — the classifier's answer is the authority),
     *  {@code CharSequence::length} (three abstract methods, so no SAM at all), and
     *  {@code Iterable::iterator} — the one that fails a {@code samNameOf}-keyed fix, because
     *  {@code x -> x.iterator()} is silent, so charging the reference would be a NEW asymmetry pointing
     *  the other way. Its lambda twin is asserted here beside it, so the row measures parity rather than
     *  a remembered expectation. */
    @Test
    void referencesThatNameNoUnpinnedJdkSamStayPure() throws Exception {
        Path cls = compile(Map.of("app/Pure.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.stream.*;",
            "public class Pure {",
            "  public long trimRef(List<String> xs)  { return xs.stream().map(String::trim).count(); }",
            "  public long nonNullRef(List<String> xs) { return xs.stream().filter(Objects::nonNull).count(); }",
            "  public long lenRef(List<CharSequence> xs) { return xs.stream().map(CharSequence::length).count(); }",
            "  public long iterRef(List<Iterable<String>> xs) { return xs.stream().map(Iterable::iterator).count(); }",
            "  public long iterLam(List<Iterable<String>> xs) { return xs.stream().map(x -> x.iterator()).count(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"trimRef", "nonNullRef", "lenRef", "iterRef"})
                assertFalse(eff(r, "app.Pure." + m).contains(Effect.UNKNOWN),
                    m + " names no unpinned JDK functional SAM — disclosing Unknown here would fabricate "
                    + "on the front door of Stream, over code the engine can already answer. Got "
                    + r.get("app.Pure." + m));
            assertEquals(eff(r, "app.Pure.iterLam"), eff(r, "app.Pure.iterRef"),
                "and iterRef is pure for the RIGHT reason — its lambda twin is pure too. A samNameOf-keyed "
                + "fix charges the reference and not the lambda, which is the fabrication this row rejects");
        } finally { rm(cls.getParent()); }
    }

    /** CHA FIRST, NOT DISCLOSURE FIRST. When the scanned project DOES implement the functional interface,
     *  {@code handleMethodInsn} resolves the lambda arm to that body and reports the PRECISE effect rather
     *  than {@code Unknown} — so the reference arm must resolve too, or this fix would trade a silence for
     *  an over-charge on every library that implements {@code Supplier}/{@code Function}. RED without the
     *  fix ({@code useRef} is absent entirely); and it is the row that would go {@code ['Unknown']} rather
     *  than {@code ['Fs']} if the CHA lookup were dropped for a bare disclosure. */
    @Test
    void aProjectImplementorResolvesRatherThanDiscloses() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Only.java", String.join("\n",
            "package app;",
            "import java.nio.file.*;",
            "import java.util.function.Supplier;",
            "public class Only implements Supplier<String> {",
            "  public String get() { try { Files.writeString(Paths.get(\"/tmp/x\"), \"x\"); }",
            "    catch (Exception e) { } return \"x\"; }",
            "}"));
        m.put("app/Use.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "import java.util.function.Supplier;",
            "public class Use {",
            "  public long useRef(List<Supplier<String>> xs) { return xs.stream().map(Supplier::get).count(); }",
            "  public long useLam(List<Supplier<String>> xs) { return xs.stream().map(s -> s.get()).count(); }",
            "}"));
        Path cls = compile(m);
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Use.useRef").contains(Effect.FS),
                "the only implementor of Supplier in scope is app.Only, whose get() writes a file — the "
                + "reference must resolve to that body exactly as the lambda arm does. Got "
                + r.get("app.Use.useRef"));
            assertFalse(eff(r, "app.Use.useRef").contains(Effect.UNKNOWN),
                "…and must NOT degrade to a disclosure when a body is reachable: that would trade this "
                + "row's silence for an over-charge wherever a library implements a JDK functional "
                + "interface. Got " + r.get("app.Use.useRef"));
            assertEquals(eff(r, "app.Use.useLam"), eff(r, "app.Use.useRef"),
                "the two spellings agree here too, which is what makes the previous two assertions a "
                + "parity measurement rather than a remembered expectation");
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
