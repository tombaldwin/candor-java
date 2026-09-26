package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R674 (rows R622 / R623 / R624) — <b>the R131 supertype walk charges an effect; does that
 * charge reach the guards a CLASSIFIED charge reaches?</b>
 *
 * <p>{@code 18752cb} extended the supertype re-classification to EXTERNAL owners and deliberately left
 * the {@code effect} local null, so that {@code crossDepJoin} / {@code externalStreamUtility} /
 * {@code entryAbstractStream} — all three gated on {@code effect == null} — kept firing. That half is
 * right and this change does not touch it. What the commit's cost sentence got wrong is the price: it
 * named ONE precision cost ("the literal surface") and omitted THREE fail-closed consumers, every one of
 * which stopped firing on precisely the rows the walk adds.
 *
 * <p><b>Every arm here is PAIRED with its classified-spelling control in the same class and the same
 * scan</b>, differing only in the STATIC RECEIVER TYPE the bytecode carries — the subtype spelling the
 * walk charges versus the modelled supertype spelling the classifier charges. That is the one variable;
 * both reach the identical syscall. The assertion in each case is PARITY, because "one syscall, two
 * spellings, two verdicts" is what these three rows are all about, and parity is the only form of the
 * claim that cannot be satisfied by making both arms wrong.
 *
 * <p><b>SOUNDNESS R683 — THE TWO R622 TESTS WERE {@code @Disabled} AND ARE LIVE AGAIN AS OF R675
 * (row R712), UNCHANGED.</b> They were written as R675's acceptance tests and were never edited to pass:
 * R674's first cut routed the walk's {@code Unknown} through {@code effectMetadata} too, which is what
 * made them green the first time — but that call's only {@code UNKNOWN} arm tagged the hole
 * {@code reflect:}, the label R675 had already filed as WRONG for a java.io filter/buffered delegation
 * (a DISPATCH, by the classifier's own comment). Measured over the 25 highest-reach census jars, the 918
 * {@code Unknown[unresolved]} holes did not move to {@code dispatch}, where
 * {@code deny Unknown[dispatch,unresolved]} would still catch them — they moved to {@code reflect}, and
 * {@code deny Unknown[unresolved]} ALONE went 918 violations to 0. So the label was withheld until the
 * class was right.
 *
 * <p><b>AND IT TOOK BOTH HALVES, WHICH IS WHY THEY LANDED IN ONE CHANGE — R675 ALONE WAS NOT ENOUGH.</b>
 * R675 relabels the delegation {@code dispatch:} at the source, which moves the SUPERTYPE spelling only;
 * while the {@code se != Effect.UNKNOWN} guard stood, the subtype spelling stayed reasonless and floored
 * at {@code {unresolved}}, so {@code deny Unknown[dispatch]} would have fired on
 * {@code FilterInputStream.read} and not on {@code DataInputStream.read} — R674's row names that exact
 * trap ("the second-spelling defect reintroduced with the classes swapped"). What these two assert is
 * reason-class PARITY between the two spellings, and parity needs the relabel AND the routed label. Both
 * are in; the guard is gone.
 *
 * <p>The other TWO tests are the fail-closed halves — {@code theWalksFsReachesTheMaskingGuard} (R623) and
 * {@code theWalksFsPoisonsTheReadWriteKind} (R624, with its {@code writeAlone} over-charge control) — and
 * neither moves an {@code Unknown[…]} count anywhere.
 *
 * <p><b>Measured against the pre-fix jar, all three reproduced:</b>
 * <ul>
 *   <li>R622 — {@code deny Unknown[reflect]} exited 1 on the {@code FilterInputStream} arm and 0 on the
 *       {@code DataInputStream} arm; {@code deny Unknown[unresolved]} did the exact reverse.</li>
 *   <li>R623 — {@code PropertyResourceBundle.getBundle("secret.config")} beside
 *       {@code new File("allowed.txt").exists()} published {@code paths:["allowed.txt"]} with
 *       {@code incomplete} ABSENT and PASSED {@code allow Fs allowed.txt} (exit 0), while the
 *       {@code ResourceBundle} spelling of the same call exited 1 on AS-EFF-008.</li>
 *   <li>R624 — {@code new FileWriter("out.txt").write("x")} beside that same bundle read reported
 *       {@code fs:["write"]}: "writes but never reads", over a read it had just charged.</li>
 * </ul>
 *
 * <p><b>The over-charge control is {@code writeAlone}</b>, and it is the half that matters most: the R624
 * fix works by POISONING {@code fsDirect}, and a poison that fires one call too wide deletes every honest
 * {@code fs:["write"]} in the corpus. It asserts the kind claim SURVIVES where nothing undetermined is
 * reached. {@code SecondSpellingRouteTest#control_sslServerSocketConfigStaysPure} is the other standing
 * control on this walk (the classifier-shape denylist) and is untouched by this change.
 */
class SupertypeWalkGuardRoutingTest {

    // ── R622: the walk's `Unknown` carries a REASON, so one syscall gets one verdict ────────────────

    /**
     * The two spellings of ONE JDK call, in one class and one scan. {@code FilterInputStream.read} is the
     * classifier's own modelled owner (it returns {@code Unknown} — a filter stream delegates to a sink of
     * unknown concrete type); {@code DataInputStream} INHERITS that exact method one hop down, so only the
     * R131 walk charges it. Before this fix the second carried no {@code unknownWhy} at all, which is the
     * single input {@code Policy.reasonClassesOf} reads: an empty token set floors at {@code {unresolved}}
     * and a non-empty one returns only what it parsed, so the two spellings landed in DIFFERENT and
     * DISJOINT reason classes and no single {@code deny Unknown[…]} rule could name both.
     */
    @Test
    void theWalksUnknownCarriesAReasonLikeItsSupertypeSpelling() throws Exception {
        Path cls = compile(Map.of("app/R.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class R {",
            // the walk's arm: DataInputStream declares no read() of its own
            "  public int viaSubtype(DataInputStream d) throws Exception { return d.read(); }",
            // the control: the modelled supertype, one hop up, same syscall
            "  public int viaSupertype(FilterInputStream f) throws Exception { return f.read(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.R.viaSubtype").contains(Effect.UNKNOWN), "the walk still charges it");
            assertTrue(eff(r, "app.R.viaSupertype").contains(Effect.UNKNOWN), "the classifier still charges it");
            assertFalse(whyOf("app.R.viaSubtype").isEmpty(),
                    "the walk's Unknown must NAME its hole — an Unknown with no reason is the only "
                    + "reasonless one in the engine, and Policy.reasonClassesOf reads nothing else");
            assertEquals(classesOf("app.R.viaSupertype"), classesOf("app.R.viaSubtype"),
                    "ONE syscall, ONE verdict: the subtype spelling must land in the same reason CLASS as "
                    + "the supertype spelling it inherits the method from, or no `deny Unknown[c]` names "
                    + "both. Got sub=" + whyOf("app.R.viaSubtype") + " sup=" + whyOf("app.R.viaSupertype"));
            assertTrue(whyOf("app.R.viaSubtype").toString().contains("java.io.DataInputStream.read"),
                    "…and it names THIS call's own owner, not the supertype the rule was found on — the "
                    + "reason is a site, and the site is here. Got " + whyOf("app.R.viaSubtype"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * The MASKING half of R622, and the reason the row is not merely cosmetic. {@code reasonClassesOf}
     * floors an EMPTY token set at {@code {unresolved}} — so before this fix the walk's hole was visible
     * to {@code deny Unknown[unresolved]} only while it was the unit's ONLY Unknown. Put any other tagged
     * Unknown in the same body and the floor lifts, and the hole is then named by no class at all: not by
     * {@code unresolved} (the set is non-empty) and not by the tagged class (it was never tagged).
     */
    @Test
    void aSecondTaggedUnknownNoLongerHidesTheWalksHole() throws Exception {
        Path cls = compile(Map.of("app/M.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class M {",
            "  public int both(DataInputStream d, FilterInputStream f) throws Exception {",
            "    return d.read() + f.read(); }",
            "  public int alone(DataInputStream d) throws Exception { return d.read(); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertTrue(whyOf("app.M.both").toString().contains("java.io.DataInputStream.read"),
                    "the walk's hole must be named in its OWN right, not left to a floor another Unknown "
                    + "lifts. Got " + whyOf("app.M.both"));
            assertEquals(classesOf("app.M.alone"), classesOf("app.M.both"),
                    "the hole's reason class must not depend on what ELSE the unit happens to reach — that "
                    + "dependence is the masking. Got both=" + whyOf("app.M.both"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * SOUNDNESS R714 — <b>THE THIRD SPELLING, and the one this vein's audit boundary kept excluding.</b>
     * {@code handleMethodInsn} runs TWO supertype re-classifications: the PROJECT-owner one
     * ({@code Candor.java:~4379}, which assigns {@code effect}) and R131's EXTERNAL-owner one below it
     * (which does not). Every row in this file, and R675's own relabel, was about the second. The first
     * has the identical shape: it charges the supertype's effect under the PROJECT class's owner name, and
     * that name matches no classifier rule, so the reason kind would come from
     * {@code Classifier.unknownKind}'s majority default rather than from the charging rule.
     *
     * <p>MEASURED before the fix existed, on this fixture: {@code viaProjectSubtype} reported
     * {@code reflect:app.T$MyStream.read} while {@code viaExternalSubtype} and {@code viaModelled}
     * reported {@code dispatch:…} — ONE syscall, THREE spellings, two classes. That is R674's named trap
     * ("the second-spelling defect reintroduced with the classes swapped") arriving one spelling further
     * out, and R675 alone would have shipped it.
     *
     * <p>The assertion is again PARITY across all three, because parity is the only form of the claim that
     * cannot be satisfied by making every arm wrong — and note that it CAN be satisfied that way, which is
     * why {@code UnknownReasonKindTableTest} exists beside this file: neutering the kind table to a bare
     * {@code return REFLECT} leaves every test in THIS class green.
     */
    @Test
    void theProjectOwnerWalksUnknownCarriesTheSameClassAsBothOtherSpellings() throws Exception {
        Path cls = compile(Map.of("app/T.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "public class T {",
            "  public static class MyStream extends FilterInputStream {",
            "    public MyStream(InputStream in) { super(in); }",
            "  }",
            // the PROJECT-owner walk's arm: owner of the invoke is app.T$MyStream
            "  public int viaProjectSubtype(MyStream m) throws Exception { return m.read(); }",
            // the R131 EXTERNAL-owner walk's arm
            "  public int viaExternalSubtype(DataInputStream d) throws Exception { return d.read(); }",
            // the classifier's own modelled owner
            "  public int viaModelled(FilterInputStream f) throws Exception { return f.read(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String fn : java.util.List.of("app.T.viaProjectSubtype", "app.T.viaExternalSubtype",
                                               "app.T.viaModelled"))
                assertTrue(eff(r, fn).contains(Effect.UNKNOWN), fn + " still charges Unknown");
            assertEquals(classesOf("app.T.viaModelled"), classesOf("app.T.viaProjectSubtype"),
                    "ONE syscall, ONE verdict — a PROJECT subclass of a modelled java.io stream must land "
                    + "in the same reason CLASS as the modelled owner it inherits the method from. Got "
                    + "project=" + whyOf("app.T.viaProjectSubtype") + " modelled="
                    + whyOf("app.T.viaModelled"));
            assertEquals(classesOf("app.T.viaExternalSubtype"), classesOf("app.T.viaProjectSubtype"),
                    "…and the same class as the EXTERNAL subtype spelling, or no single `deny Unknown[c]` "
                    + "names all three. Got project=" + whyOf("app.T.viaProjectSubtype") + " external="
                    + whyOf("app.T.viaExternalSubtype"));
            assertTrue(whyOf("app.T.viaProjectSubtype").toString().contains("app.T$MyStream.read"),
                    "…and the detail names THIS call's own owner, not the supertype the rule was found on. "
                    + "Got " + whyOf("app.T.viaProjectSubtype"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * SOUNDNESS R717 — <b>THE PROJECT-OWNER WALK UNIONS INTO {@code dir} AND KEEPS ONE {@code effect}, SO
     * THE UNION CAN OUTLIVE THE LOCAL.</b> That loop writes every matching supertype's effect into
     * {@code dir} but overwrites {@code effect} each time, and {@code effectMetadata} — the only route that
     * names an {@code Unknown} at that call site — reads {@code effect}. So two modelled supertypes
     * DISAGREEING, with {@code Unknown} not last in {@code transSupers}' HashSet order, publish
     * {@code Unknown} in {@code inferred} while the reason arm never runs: R716's reasonless charge again, by
     * a different mechanism, in the block R714's own fix had just touched. The comment that stood there said
     * a later concrete {@code effect} "leaves it harmlessly set" — §K, in the sentence that needed it to be
     * true.
     *
     * <p><b>REACHED, and a probe rather than a reading is what established that.</b> The walk consults
     * {@code classify} per supertype and never asks whether that supertype DECLARES the member, so a
     * WHOLE-OWNER rule anywhere in the hierarchy collides with every other rule in it:
     * {@code java.util.random.RandomGenerator} answers {@code Rand} for any name and
     * {@code java.io.FilterInputStream} answers {@code Unknown} for {@code read}. Measured on the pre-fix
     * jar, {@code twoSupersDisagree} reported {@code inferred:['Rand','Unknown']} with {@code unknownWhy}
     * ABSENT, against {@code dispatch:…} on the one-super control in the same scan.
     *
     * <p><b>AND THE SHAPE IS BROAD, WHICH THE FIRST PROBE GOT WRONG.</b> A probe restricted to each owner's
     * DECLARED methods found every disagreeing pair to be two unrelated classes and concluded "not a class" —
     * its boundary was its own trigger (§9). The walk never asks whether the supertype declares the member,
     * so the right cross is owner literals against ALL probe keys: **243 distinct disagreeing pairs are
     * co-inheritable with both sides loadable, 212 of them JDK-only**, pairing 23 UNKNOWN-side JDK owners
     * against blanket-ruled interfaces ({@code RandomGenerator}, {@code ProcessHandle}, {@code Registry}) and
     * whole-owner classes; 6,307 further pair shapes involve a third-party owner off this classpath and could
     * not be decided. What is rare is a real project doing it: R717's reach over the 452-jar census is ZERO,
     * so this arm is a FIXTURE-only demonstration and the corpus A/B is safety-only for it.
     *
     * <p><b>THE RESIDUAL, STATED.</b> Which supertype wins {@code effect} is {@code transSupers}' HashSet
     * order, so this fixture exercises the RESCUE only while that order puts {@code RandomGenerator} last —
     * which it does on JDK 21, verified by CALIBRATION: reverting the two lines in {@code handleMethodInsn}
     * turns this test RED and nothing else in this class. It cannot be asserted from inside the test, because
     * the rescue and {@code effectMetadata} produce the byte-identical token by design; the calibration is
     * the evidence and it is in the commit message.
     */
    @Test
    void theProjectOwnerWalksUnknownIsNamedEvenWhenAnotherSuperWinsTheEffectLocal() throws Exception {
        Path cls = compile(Map.of("app/W.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.util.random.RandomGenerator;",
            "public class W {",
            // TWO modelled external supers, disagreeing on `read()I`: Unknown (delegation) vs Rand (blanket)
            "  public abstract static class TwoSupers extends FilterInputStream implements RandomGenerator {",
            "    protected TwoSupers(InputStream in) { super(in); }",
            "  }",
            // the one-super control: `effect` can only end as UNKNOWN here
            "  public abstract static class OneSuper extends FilterInputStream {",
            "    protected OneSuper(InputStream in) { super(in); }",
            "  }",
            "  public int twoSupersDisagree(TwoSupers t) throws Exception { return t.read(); }",
            "  public int oneSuperOnly(OneSuper o) throws Exception { return o.read(); }",
            "  public int viaModelled(FilterInputStream f) throws Exception { return f.read(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.W.twoSupersDisagree").contains(Effect.UNKNOWN),
                    "the union still charges Unknown — R717 names it, it does not add or remove it. Got "
                    + eff(r, "app.W.twoSupersDisagree"));
            assertTrue(eff(r, "app.W.twoSupersDisagree").contains(Effect.RAND),
                    "…and still charges the OTHER supertype's effect: the union is the sound answer, and the "
                    + "fix must not narrow it to whichever one won the local. Got "
                    + eff(r, "app.W.twoSupersDisagree"));
            assertFalse(whyOf("app.W.twoSupersDisagree").isEmpty(),
                    "an Unknown the walk charged must NAME its hole whatever `effect` ended up as — "
                    + "`effectMetadata` reads `effect`, and the union does not");
            assertEquals(classesOf("app.W.oneSuperOnly"), classesOf("app.W.twoSupersDisagree"),
                    "ONE syscall, ONE verdict: the reason class must not turn on whether a SECOND modelled "
                    + "supertype happened to be iterated after the Unknown-charging one. Got two="
                    + whyOf("app.W.twoSupersDisagree") + " one=" + whyOf("app.W.oneSuperOnly"));
            assertEquals(classesOf("app.W.viaModelled"), classesOf("app.W.twoSupersDisagree"),
                    "…and the same class as the modelled owner it inherits the method from. Got two="
                    + whyOf("app.W.twoSupersDisagree") + " modelled=" + whyOf("app.W.viaModelled"));
            assertTrue(whyOf("app.W.twoSupersDisagree").toString().contains("app.W$TwoSupers.read"),
                    "…and the detail names THIS call's own owner, as every other arm in this file does. Got "
                    + whyOf("app.W.twoSupersDisagree"));
        } finally { rm(cls.getParent()); }
    }

    // ── R623: the walk's `Fs` reaches the masking guards ────────────────────────────────────────────

    /**
     * {@code ResourceBundle.getBundle(String)} is classified {@code Fs} (it reads a properties file off
     * the classpath/disk) and its locator is a runtime-or-literal String on an owner this engine does not
     * construct from a path, so the R433/R465 branch DISCLOSES: {@code incomplete:["Fs"]}.
     * {@code PropertyResourceBundle} inherits that static one hop down, so only the walk charges it — and
     * {@code extractLiteralSurfaces} never ran, so the surface came back certifiable. Beside one benign
     * captured literal that is a fail-OPEN: {@code allow Fs allowed.txt} exited 0 over a read of
     * {@code secret.config}, while the supertype spelling of the same call exited 1.
     */
    @Test
    void theWalksFsReachesTheMaskingGuard() throws Exception {
        Path cls = compile(Map.of("app/F.java", String.join("\n",
            "package app;",
            "import java.io.File;",
            "import java.util.PropertyResourceBundle;",
            "import java.util.ResourceBundle;",
            "public class F {",
            "  public boolean viaSubtype() {",
            "    boolean ok = new File(\"allowed.txt\").exists();",
            "    ResourceBundle b = PropertyResourceBundle.getBundle(\"secret.config\");",
            "    return ok && b != null; }",
            "  public boolean viaSupertype() {",
            "    boolean ok = new File(\"allowed.txt\").exists();",
            "    ResourceBundle b = ResourceBundle.getBundle(\"secret.config\");",
            "    return ok && b != null; }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.F.viaSubtype").contains(Effect.FS), "the walk still charges Fs");
            assertTrue(inc("app.F.viaSupertype"), "the control: the classified spelling discloses");
            assertTrue(inc("app.F.viaSubtype"),
                    "an Fs the walk charged reads a file the gate cannot see — the surface is INCOMPLETE. "
                    + "Without this, one benign sibling literal certifies the whole unit under a scoped "
                    + "`allow Fs`, which is the fail-open this row was filed for");
        } finally { rm(cls.getParent()); }
    }

    // ── R624: the walk's `Fs` poisons the read/write kind ───────────────────────────────────────────

    /**
     * PART 31's partial-positive claim, arriving through the walk. {@code fsFixpoint} seeds only from
     * {@code fsDirect}, which only {@code effectMetadata} writes — so a bundle READ the walk charged
     * contributed no kind at all and the neighbouring {@code FileWriter} write stood alone:
     * {@code fs:["write"]}, i.e. "writes but never reads", over a read in the same body.
     *
     * <p>{@code writeAlone} is the OVER-CHARGE CONTROL and the more important half. The fix works by
     * poisoning, and a poison one call too wide silently deletes every honest kind claim in the corpus.
     */
    @Test
    void theWalksFsPoisonsTheReadWriteKind() throws Exception {
        Path cls = compile(Map.of("app/K.java", String.join("\n",
            "package app;",
            "import java.io.FileWriter;",
            "import java.util.PropertyResourceBundle;",
            "import java.util.ResourceBundle;",
            "public class K {",
            "  public void viaSubtype() throws Exception {",
            "    new FileWriter(\"out.txt\").write(\"x\");",
            "    ResourceBundle b = PropertyResourceBundle.getBundle(\"msgs\");",
            "    if (b == null) throw new IllegalStateException(); }",
            "  public void viaSupertype() throws Exception {",
            "    new FileWriter(\"out.txt\").write(\"x\");",
            "    ResourceBundle b = ResourceBundle.getBundle(\"msgs\");",
            "    if (b == null) throw new IllegalStateException(); }",
            "  public void writeAlone() throws Exception {",
            "    new FileWriter(\"out.txt\").write(\"x\"); }",
            "}")));
        try {
            Candor.runScan(cls);
            assertFalse(claimsKind("app.K.viaSupertype"), "the control: the classified spelling makes no claim");
            assertFalse(claimsKind("app.K.viaSubtype"),
                    "a unit reaching an Fs of UNDETERMINED kind must make no read/write claim at all — "
                    + "reporting `write` beside a charged read is the partial positive claim PART 31 and "
                    + "effectMetadata's own comment forbid. Got " + kindOf("app.K.viaSubtype"));
            assertTrue(claimsKind("app.K.writeAlone"),
                    "OVER-CHARGE CONTROL: a unit whose every Fs kind IS determined must still publish it. "
                    + "The fix poisons; a poison that fires here deletes every honest kind in the corpus");
            assertEquals(new TreeSet<>(java.util.List.of("write")), kindOf("app.K.writeAlone"),
                    "…and it is still `write`, unchanged");
        } finally { rm(cls.getParent()); }
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** The {@code unknownWhy} reasons recorded for {@code fn} by the scan just run. */
    private static TreeSet<UnknownReason> whyOf(String fn) {
        return AnalysisState.ctx().unknownWhy.getOrDefault(fn, new TreeSet<>());
    }

    /** The §6.2 reason CLASSES those reasons project to — what a {@code deny Unknown[c…]} filter reads. */
    private static TreeSet<String> classesOf(String fn) {
        TreeSet<String> out = new TreeSet<>();
        for (UnknownReason r : whyOf(fn)) out.add(io.poly.candor.model.ReasonClass.of(r).token());
        return out;
    }

    private static boolean inc(String fn) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>()).contains("Fs");
    }

    /** The DIRECT Fs read/write kinds recorded for {@code fn}, poison included. */
    private static TreeSet<String> kindOf(String fn) {
        return AnalysisState.ctx().fsDirect.getOrDefault(fn, new TreeSet<>());
    }

    /** Whether the report would publish a read/write claim — a kind set that is non-empty and unpoisoned. */
    private static boolean claimsKind(String fn) {
        TreeSet<String> k = kindOf(fn);
        return !k.isEmpty() && !k.contains(Candor.FS_UNKNOWN);
    }
}
