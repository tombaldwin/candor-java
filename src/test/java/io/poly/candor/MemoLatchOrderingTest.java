package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.MethodInsnNode;

/**
 * A MEMO COMPUTED OVER INCOMPLETE STATE OUTLIVES THE STATE.
 *
 * <p>Swept into java from candor-rust, where a parser abort wrote an empty result into the incremental
 * cache and a warm run reused it — a fail-CLOSED crash cached as a false all-clear. The java analogue is
 * a lazily-built index whose "built" latch is set unconditionally: build it once while the input map is
 * still empty and it stays empty for the whole scan, with every later consultation answering "nothing
 * there" and whatever disclosure it gates falling silent.
 *
 * <p>{@code runScan}'s ordering is what keeps this dormant today — {@code loadCrossDeps} populates
 * {@code crossDeps} at step 5, and the only caller of {@code depDeclaresSigElsewhere} runs in the
 * per-class analyze pass at step 6. That is an argument about a CALLER, though, and this file is the
 * assertion about the method itself, so a future reordering fails a test instead of silently arming a
 * cache. Its two siblings, {@code depFnsOfType} and {@code depFnsNamed}, already guard this way.
 */
class MemoLatchOrderingTest {

    @BeforeEach void fresh() { Candor.resetState(); }

    private static MethodInsnNode call(String owner, String name, String desc) {
        return new MethodInsnNode(Opcodes.INVOKEINTERFACE, owner, name, desc, true);
    }

    /** Consulted while {@code crossDeps} is still empty — the state runScan is in before step 5 — it must
     *  answer honestly AND leave itself rebuildable. */
    @Test
    void anEmptyCrossDepMapMustNotLatchTheSignatureIndex() {
        assertTrue(ctx().crossDeps.isEmpty(), "precondition: nothing chained yet");
        assertFalse(Candor.depDeclaresSigElsewhere(ctx(), call("lib/Store", "save", "(Ljava/lang/String;)V")),
                "with nothing chained there is no evidence, and false is the honest answer");
        assertFalse(ctx().depOwnersBySigBuilt,
                "…but it must NOT record that it has built the index: the latch is permanent and nothing "
                + "rebuilds it, so a build over an empty map would answer `the dep declares nothing` for "
                + "the rest of the scan, silencing the disclosure conjunct 5 gates");
    }

    /** …and once a report IS chained the index builds and answers, so the guard is not a mute button. */
    @Test
    void afterAReportIsChainedTheIndexBuildsAndAnswers(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("lib.json"),
            "{\"candor\":{\"version\":\"vSAME\",\"spec\":\"0.9\"},\"functions\":["
            + "{\"fn\":\"lib.FileStore.save\",\"hash\":\"lib/FileStore.save(Ljava/lang/String;)V\","
            + "\"inferred\":[\"Fs\"]}]}");
        Loader.loadCrossDeps(dir.toString(), "vSAME");
        assertTrue(Candor.depDeclaresSigElsewhere(ctx(), call("lib/Store", "save", "(Ljava/lang/String;)V")),
                "an effectful body with this exact name+desc under ANOTHER owner is the evidence");
        assertTrue(ctx().depOwnersBySigBuilt, "and now the index is genuinely built");
        // The same consultation ordered the other way round — the hazard, played out. Without the guard
        // the first (empty) call latches and this second one answers false forever.
        Candor.resetState();
        assertFalse(Candor.depDeclaresSigElsewhere(ctx(), call("lib/Store", "save", "(Ljava/lang/String;)V")));
        Loader.loadCrossDeps(dir.toString(), "vSAME");
        assertTrue(Candor.depDeclaresSigElsewhere(ctx(), call("lib/Store", "save", "(Ljava/lang/String;)V")),
                "consulted BEFORE the chain loaded and again after, the second answer must be the true one "
                + "— this is the whole defect, and it is a property of the method, not of runScan's order");
    }
}
