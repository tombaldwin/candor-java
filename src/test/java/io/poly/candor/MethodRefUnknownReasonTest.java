package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R716 — <b>a method REFERENCE to a classifier-{@code Unknown} non-project target charged
 * {@code Unknown} WITH NO REASON AT ALL.</b>
 *
 * <p><b>THE DEFECT, MEASURED ON THE PRE-FIX JAR.</b> {@code LongUnaryOperator op = u::getLong} reported
 * {@code inferred:['Unknown']} with {@code unknownWhy} ABSENT and {@code calls} ABSENT — so there was no
 * callee to inherit a reason from either — while the DIRECT call {@code u.getLong(addr)} in the SAME class
 * and the SAME scan reported {@code native:sun.misc.Unsafe.getLong}. One variable: the spelling. SPEC §4's
 * reason class is what {@code deny Unknown[class…]} quantifies over, so the reference form was invisible to
 * every scoped gate the call form fires.
 *
 * <p><b>WHY IT MATTERED RATHER THAN BEING UNTIDY.</b> {@code Policy.reasonClassesOf} floors an EMPTY token
 * set at {@code {unresolved}} and otherwise returns only the tokens it PARSED. So a reasonless charge is
 * visible to {@code deny Unknown[unresolved]} exactly while it is the unit's ONLY {@code Unknown}; put any
 * tagged one beside it and the floor lifts and the hole is named by no class at all — not by
 * {@code unresolved} (the set is non-empty) and not by the tagged class (it was never tagged).
 * {@code Policy}'s own comment asserted the opposite — <i>"a reasonless direct Unknown has already
 * CONTRIBUTED {@code unresolved} at its source"</i> — which was false on the scan route for precisely
 * these charges. {@link #aSecondTaggedUnknownDoesNotHideTheMethodRefsHole} is that masking arm.
 *
 * <p><b>IT CORRECTS R622's CENSUS, AND HOW IT ESCAPED IT IS THE REUSABLE PART.</b> R622 enumerated all 21
 * {@code dir.add(Effect.UNKNOWN)} sites and concluded R131's walk held the only reasonless one. This is the
 * 22nd, and it adds a VARIABLE ({@code dir.add(eff)}) — a grep for the literal cannot see a charge spelled
 * that way. That is §F1 q7 (a key two paths spell differently) applied to the AUDIT rather than to the
 * engine: a boundary drawn around a spelling, in a sweep whose whole subject was spellings. The re-census
 * that found it enumerated every READER of a classifier {@code Unknown} instead — six
 * {@code Classifier.classify(} call sites and five {@code dir.add(<non-literal>)} sites.
 *
 * <p><b>THE KIND IS READ OFF THE RULE, NOT SET TO A CONSTANT (§G).</b> {@code Classifier.unknownKind} is
 * the same authority {@code effectMetadata} asks on the direct-call path, and the handle carries the exact
 * owner the classifier just answered for — so unlike the R131 walk there is no supertype to read the rule
 * off and no second copy of a rule's condition to drift. {@link #everyReasonKindArrivesFromTheRule} is
 * three references onto three different kinds ({@code native}, {@code reflect}, {@code dispatch}) and
 * fails if any of them is answered by the majority default.
 *
 * <p><b>THE OVER-CHARGE CONTROLS ARE SHAPED SO THEY CANNOT PASS VACUOUSLY (§E3).</b> An absent unit and a
 * pure one are the same bytes, so {@code String::trim} and {@code Objects::nonNull} are placed beside a
 * {@code Clock} call: the assertion is that the unit IS present carrying {@code Clock} and is NOT charged
 * {@code Unknown}, which a broken engine that dropped the whole unit would fail.
 *
 * <p><b>NAMING ONLY.</b> Every arm here asserts that {@code inferred} is UNCHANGED by the fix and only
 * {@code unknownWhy} gains. That is the distinction R675 was filed apart from R674 to keep measurable: a
 * hole-NAMING change adds a token and moves no effect; a RELABEL moves gates both ways.
 */
class MethodRefUnknownReasonTest {

    /** The SAMs the fixtures need. {@code java.util.function} cannot express a reference to a method that
     *  throws a checked exception, and three of the four interesting targets do. */
    private static final String SAMS = String.join("\n",
        "  public interface Loader { Class<?> load(String n) throws Exception; }",
        "  public interface IoRead { int read(java.io.FilterInputStream f) throws Exception; }");

    /**
     * THE ROW'S OWN PAIR: the reference and the direct call to ONE target, in one class and one scan, with
     * the SPELLING as the only variable. Both arms must land on the same reason CLASS and the same reason
     * DETAIL — the detail matters because a second spelling of one fact is §F1 q7, and a consumer joining
     * {@code unknownWhy} tokens across the two forms has to see one token, not two.
     */
    @Test
    void theMethodRefsUnknownCarriesTheSameReasonAsTheDirectCall() throws Exception {
        Path cls = compile(Map.of("app/R.java", String.join("\n",
            "package app;",
            "import java.util.function.LongUnaryOperator;",
            "import java.util.stream.LongStream;",
            "public class R {",
            // the DIRECT call — the control
            "  public static long viaCall(sun.misc.Unsafe u, long addr) { return u.getLong(addr); }",
            // the REFERENCE to the very same target, handed to a stage that runs it
            "  public static long viaRef(sun.misc.Unsafe u, long addr) {",
            "    return LongStream.of(addr).map(u::getLong).sum(); }",
            // …and the same reference merely stowed, which is the shape the row was filed from
            "  public static LongUnaryOperator viaRefStored(sun.misc.Unsafe u) { return u::getLong; }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String fn : List.of("app.R.viaCall", "app.R.viaRef", "app.R.viaRefStored"))
                assertTrue(eff(r, fn).contains(Effect.UNKNOWN), fn + " charges Unknown (unchanged by R716)");
            assertFalse(whyOf("app.R.viaRef").isEmpty(),
                    "a method REFERENCE to a classifier-Unknown target must NAME its hole. It has no `calls` "
                    + "entry to inherit one from, and Policy.reasonClassesOf reads nothing else");
            assertEquals(whyOf("app.R.viaCall").toString(), whyOf("app.R.viaRef").toString(),
                    "ONE target, ONE token: the reference spelling must produce the reason the direct call "
                    + "produces, detail included, or a consumer joining on the token sees two facts where "
                    + "there is one. Got ref=" + whyOf("app.R.viaRef") + " call=" + whyOf("app.R.viaCall"));
            assertEquals(whyOf("app.R.viaCall").toString(), whyOf("app.R.viaRefStored").toString(),
                    "…and the STOWED reference too: `dir.add(eff)` at that site is not gated on `deferred`, "
                    + "so the charge is made and must be named. Got " + whyOf("app.R.viaRefStored"));
            assertTrue(whyOf("app.R.viaRef").toString().contains("native:sun.misc.Unsafe.getLong"),
                    "…and the kind comes from the RULE (Unsafe is the FFI/native boundary), not from the "
                    + "classifier's majority default. Got " + whyOf("app.R.viaRef"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * THE MASKING ARM, and the reason the row is not cosmetic. A reasonless token contributes NOTHING to
     * {@code reasonClassesOf}: the {@code {unresolved}} floor fires only on an EMPTY set. So before the fix
     * a unit reaching both a method-ref hole and any tagged {@code Unknown} put the ref's hole in no class
     * at all, and {@code Policy}'s comment claiming it had "already CONTRIBUTED unresolved at its source"
     * was false on the scan route.
     *
     * <p>Asserted as PARITY with the same reference ALONE, because "the hole's class must not depend on what
     * else the unit happens to reach" is the property, and parity is the only form of it that cannot be
     * satisfied by making both arms wrong.
     */
    @Test
    void aSecondTaggedUnknownDoesNotHideTheMethodRefsHole() throws Exception {
        Path cls = compile(Map.of("app/M.java", String.join("\n",
            "package app;",
            "import java.util.stream.LongStream;",
            "public class M {",
            "  public static long both(sun.misc.Unsafe u, long addr, java.lang.reflect.Method m) throws Exception {",
            "    long n = LongStream.of(addr).map(u::getLong).sum();",   // the ref hole
            "    m.invoke(null);",                                       // a TAGGED Unknown beside it
            "    return n; }",
            "  public static long alone(sun.misc.Unsafe u, long addr) {",
            "    return LongStream.of(addr).map(u::getLong).sum(); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(classesOf("app.M.both").contains("native"),
                    "the ref's hole must be named in its OWN right, not left to a floor the neighbouring "
                    + "`reflect:` token lifts. Got " + whyOf("app.M.both"));
            assertTrue(classesOf("app.M.both").containsAll(classesOf("app.M.alone")),
                    "the hole's reason class must not depend on what ELSE the unit reaches — that dependence "
                    + "IS the masking. Got both=" + whyOf("app.M.both") + " alone=" + whyOf("app.M.alone"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * THREE REFERENCES ONTO THREE DIFFERENT REASON KINDS. {@code Unsafe.getLong} is the FFI/native
     * boundary, {@code Class.forName} is core reflection, and {@code FilterInputStream.read} is the java.io
     * DELEGATION — one {@code dispatch:} rule the R675 table separates from the other 37. If this site had
     * been fixed with a constant (which is what {@code effectMetadata} itself carried until R675), two of
     * these three would be wrong and every scoped gate over them would be asking the wrong question.
     */
    @Test
    void everyReasonKindArrivesFromTheRule() throws Exception {
        Path cls = compile(Map.of("app/K.java", String.join("\n",
            "package app;",
            "import java.util.stream.LongStream;",
            "import java.util.stream.Stream;",
            "public class K {",
            SAMS,
            "  public static long nativeKind(sun.misc.Unsafe u, long addr) {",
            "    return LongStream.of(addr).map(u::getLong).sum(); }",
            "  public static Loader reflectKind() { return Class::forName; }",
            "  public static IoRead dispatchKind() { return java.io.FilterInputStream::read; }",
            "}")));
        try {
            Candor.runScan(cls);
            assertEquals(new TreeSet<>(List.of("native")), classesOf("app.K.nativeKind"),
                    "Unsafe is machine code behind an intrinsic. Got " + whyOf("app.K.nativeKind"));
            assertEquals(new TreeSet<>(List.of("reflect")), classesOf("app.K.reflectKind"),
                    "Class.forName chooses its target from data. Got " + whyOf("app.K.reflectKind"));
            assertEquals(new TreeSet<>(List.of("dispatch")), classesOf("app.K.dispatchKind"),
                    "a filter stream forwards to a wrapped sink whose concrete type this scan never saw — an "
                    + "owner type was formed and the member is named, which is what §4 keys `dispatch:` on. "
                    + "Got " + whyOf("app.K.dispatchKind"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * THE OVER-CHARGE CONTROLS. {@code classify} answers null for {@code String.trim} and
     * {@code Objects.nonNull}, so nothing is added and nothing may be named — the fix is inside
     * {@code if (eff == Effect.UNKNOWN)} and must not widen the charge itself.
     *
     * <p>Shaped against §E3: an ABSENT unit and a PURE one are the same bytes, so each control sits beside a
     * {@code Clock} call and the assertion is that the unit IS present carrying {@code Clock} while carrying
     * NO {@code Unknown} and NO reason. A broken engine that dropped the unit fails the first half; one that
     * over-charged fails the second.
     */
    @Test
    void aPureMethodRefIsNeitherChargedNorNamed() throws Exception {
        Path cls = compile(Map.of("app/P.java", String.join("\n",
            "package app;",
            "import java.util.List;",
            "import java.util.Objects;",
            "public class P {",
            "  public static long trimmed(List<String> xs) {",
            "    xs.stream().map(String::trim).forEach(s -> {});",
            "    return System.currentTimeMillis(); }",
            "  public static long nonNulls(List<Object> xs) {",
            "    xs.stream().filter(Objects::nonNull).forEach(s -> {});",
            "    return System.currentTimeMillis(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String fn : List.of("app.P.trimmed", "app.P.nonNulls")) {
                assertTrue(eff(r, fn).contains(Effect.CLOCK),
                        fn + " must be PRESENT and carry Clock — otherwise `no Unknown here` is a claim "
                        + "about nothing, which is what an absence control has to rule out first");
                assertFalse(eff(r, fn).contains(Effect.UNKNOWN),
                        fn + " must not be charged: classify answers null for this target, and R716 only "
                        + "NAMES a charge that was already made. Got " + eff(r, fn));
                assertTrue(whyOf(fn).isEmpty(), fn + " must carry no reason either. Got " + whyOf(fn));
            }
        } finally { rm(cls.getParent()); }
    }

    // ── helpers (same shape as SupertypeWalkGuardRoutingTest's, deliberately) ────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    private static TreeSet<UnknownReason> whyOf(String fn) {
        return AnalysisState.ctx().unknownWhy.getOrDefault(fn, new TreeSet<>());
    }

    /** The §6.2 reason CLASSES those reasons project to — what a {@code deny Unknown[c…]} filter reads. */
    private static TreeSet<String> classesOf(String fn) {
        TreeSet<String> out = new TreeSet<>();
        for (UnknownReason r : whyOf(fn)) out.add(io.poly.candor.model.ReasonClass.of(r).token());
        return out;
    }
}
