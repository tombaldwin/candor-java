package io.poly.candor;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.UnknownReason;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R218 — <b>ONE FACT MUST NOT BE SPELLED TWO WAYS IN ONE REPORT.</b> {@code
 * handleInvokeDynamic}'s project-owner branch built its {@code dispatch:} detail from {@code
 * h.getOwner()}, which is an ASM INTERNAL name, so it emitted {@code dispatch:java/lang/Runnable.run}
 * while the other eight producers — all reached through {@code handleMethodInsn}, whose {@code owner}
 * local is {@code min.owner.replace('/', '.')} — emitted the dotted form of the same fact. That is §F1
 * q7: a key two paths spell differently, and it defeats exactly the grouping {@code unknownWhy} exists
 * for.
 *
 * <p><b>Measured on the 452-jar census, PRE.</b> 105 slashed details in 18 jars, and on three of them the
 * VERY SAME owner+member appeared under both spellings in ONE report —
 * {@code redis/clients/jedis/Builder.build} beside {@code redis.clients.jedis.Builder.build} (jedis-5.1.3
 * and 6.0.0), {@code reactor/core/CoreSubscriber.currentContext} (reactor-core 3.6.7 and 3.8.0-M3), and
 * four owners at once in ant-1.10.14. POST: 0 slashed details in 452 jars.
 *
 * <p><b>The A/B, wide key, 452 jars / 1,220,848 rows: ADDED 0, REMOVED 0, CHANGED 99</b> (0.0081%), and
 * the {@code inferred}-only key changes 0. All 99 audited in full: {@code unknownWhy} is the ONLY field
 * that differs on any of them — 84 pure re-spellings and 15 rows where the pre-image carried BOTH
 * spellings and the post-image carries one, which is the defect collapsing. Gate parity: 108 pairs
 * (6 policy forms x the 18 touched jars), 0 exit-code and 0 violation-count differences — as expected,
 * since the reason KIND is {@code DISPATCH} on both sides and {@code Policy.reasonClassesOf} reads the
 * kind, not the detail.
 *
 * <p><b>Why this fixture and not the JDK SAM.</b> The branch is the PROJECT-owner one, so the referenced
 * SAM must be declared in the scan; and it only reaches the disclosure arm when the CHA fan-out exceeds
 * {@code CHA_FANOUT_LIMIT} on an open hierarchy. Thirteen implementors is the smallest count that does —
 * {@link #twelveImplementorsIsTheControlThatKeepsThisArmHonest} pins the other side of that bound, so a
 * green here cannot come from the arm never firing.
 */
class DispatchReasonSpellingTest {

    /** The referencing unit. The method reference must be CONSUMED at its creation site: a ref that is
     *  RETURNED (or stowed in a deferred factory) is {@code lambdaEscapesUninvoked} and the project-owner
     *  branch deliberately skips it, so a `return Sam::size;` fixture never reaches the code under test —
     *  measured, it produced zero `dispatch:` reasons. Handing it straight to `mapToInt` is a call that
     *  RUNS it. */
    private static final String USE = String.join("\n",
            "package app;",
            "import java.util.stream.Stream;",
            "public class Use {",
            "  public int total(Stream<Sam> s) { return s.mapToInt(Sam::size).sum(); }",
            "}", "");

    /** A project SAM, N implementors of it, and a METHOD REFERENCE to the SAM's own member — which is what
     *  routes through {@code handleInvokeDynamic}'s project-owner branch rather than {@code
     *  handleMethodInsn}. */
    private static Path fixture(int implementors) throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("app/Sam.java", "package app;\npublic interface Sam { int size(); }\n");
        for (int i = 1; i <= implementors; i++) {
            src.put("app/Impl" + i + ".java",
                    "package app;\npublic class Impl" + i + " implements Sam { public int size() { return "
                    + i + "; } }\n");
        }
        src.put("app/Use.java", USE);
        return compile(src);
    }

    private static TreeSet<UnknownReason> whyOf(String fn) {
        return AnalysisState.ctx().unknownWhy.getOrDefault(fn, new TreeSet<>());
    }

    /** Every {@code dispatch:} detail this scan recorded anywhere, so nothing is asserted about only the
     *  one unit the author had in mind (§9 — the audit boundary must not be drawn around its trigger). */
    private static TreeSet<String> everyDispatchDetail() {
        TreeSet<String> out = new TreeSet<>();
        for (TreeSet<UnknownReason> set : AnalysisState.ctx().unknownWhy.values())
            for (UnknownReason r : set)
                if (r.kind() == UnknownReason.Kind.DISPATCH) out.add(r.detail());
        return out;
    }

    /**
     * THE ARM. A method reference to a project SAM with a fan-out past the bound discloses {@code
     * dispatch:} — and spells the owner DOTTED, the way every other producer in the engine does.
     */
    @Test
    void theIndyProjectOwnerBranchSpellsItsOwnerDOTTED() throws Exception {
        Path cls = fixture(13);
        try {
            Candor.runScan(cls);
            TreeSet<String> details = everyDispatchDetail();
            assertFalse(details.isEmpty(),
                    "THE ARM DID NOT FIRE — no `dispatch:` reason anywhere, so a pass below would be "
                    + "vacuous. 13 implementors of a project SAM reached through a method reference is "
                    + "supposed to exceed CHA_FANOUT_LIMIT and disclose.");
            assertTrue(details.contains("app.Sam.size"),
                    "the indy project-owner branch must name its owner DOTTED, like handleMethodInsn's "
                    + "eight producers. Got " + details);
            for (String d : details) {
                assertFalse(d.contains("/"),
                        "SOUNDNESS R218: a `dispatch:` detail carrying an ASM INTERNAL name is the same "
                        + "fact spelled a second way, and a consumer grouping on unknownWhy then sees two "
                        + "reasons where there is one. Got " + d + " among " + details);
            }
        } finally { rm(cls.getParent()); }
    }

    /**
     * THE CONTROL FOR THE BOUND. Twelve implementors is inside {@code CHA_FANOUT_LIMIT}, so the reference
     * RESOLVES and there is no {@code dispatch:} disclosure at all. Without this, a future change that
     * silenced the arm entirely would leave the test above green for the wrong reason — which is the
     * unfalsifiable-green shape this repo's own brief calls out.
     */
    @Test
    void twelveImplementorsIsTheControlThatKeepsThisArmHonest() throws Exception {
        Path cls = fixture(12);
        try {
            Candor.runScan(cls);
            assertEquals(new TreeSet<String>(), everyDispatchDetail(),
                    "inside the fan-out bound the reference resolves, so there is nothing to disclose — "
                    + "if this ever fires, the bound moved and the 13-implementor arm above is no longer "
                    + "measuring the branch it names");
            assertTrue(whyOf("app.Use.total").isEmpty(),
                    "…and the referencing unit itself carries no hole. Got " + whyOf("app.Use.total"));
        } finally { rm(cls.getParent()); }
    }

    /**
     * THE SIBLING PRODUCER, pinned in the SAME scan so the two can never drift apart again. The
     * {@code samCha} arm one branch over already dotted its owner and said so in a comment naming this
     * defect as "a separate, pre-existing defect"; both now dot, and a scan that reaches both must produce
     * one spelling.
     */
    @Test
    void theJdkSamSpellingAndTheProjectSamSpellingAgree() throws Exception {
        Map<String, String> src = new LinkedHashMap<>();
        src.put("app/Sam.java", "package app;\npublic interface Sam { int size(); }\n");
        for (int i = 1; i <= 13; i++)
            src.put("app/Impl" + i + ".java",
                    "package app;\npublic class Impl" + i + " implements Sam { public int size() { return "
                    + i + "; } }\n");
        src.put("app/Use.java", String.join("\n",
                "package app;",
                "import java.util.stream.Stream;",
                "public class Use {",
                "  public int total(Stream<Sam> s) { return s.mapToInt(Sam::size).sum(); }",
                // the CLASSIFIED spelling of an inherited JDK delegation, in one scan with the above
                "  public int filt(java.io.FilterInputStream f) throws java.io.IOException "
                + "{ return f.read(); }",
                "  public int data(java.io.DataInputStream d) throws java.io.IOException "
                + "{ return d.read(); }",
                "}", ""));
        Path cls = compile(src);
        try {
            Candor.runScan(cls);
            TreeSet<String> details = everyDispatchDetail();
            assertTrue(details.size() >= 3, "all three producers must have fired. Got " + details);
            for (String d : details)
                assertFalse(d.contains("/"), "one report, one spelling. Got " + d + " among " + details);
        } finally { rm(cls.getParent()); }
    }
}
