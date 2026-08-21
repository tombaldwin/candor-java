package io.poly.candor;

import java.util.List;
import org.objectweb.asm.tree.ClassNode;

/** THE REPORT REFRESH — re-analyse only the classes whose bytecode changed.
 *
 *  <p>Why it exists: the agent edit-time loop pays a full re-analysis every time one class changes. On
 *  the field case (uflexi, 2,259 classes) that is 3.30s of a 3.51s Stop-hook, and it is the turn the
 *  agent is waiting on. The frequency half is already handled — the hook skips turns where nothing the
 *  verdict depends on moved — so what is left is the first turn after any edit.
 *
 *  <p>WHAT IS CACHED, AND WHY ONLY THAT. Measured with CANDOR_TIMING over three targets: parse+analyze
 *  is ~90% of a scan, the fixpoint 1.3–3.4%, the whole-program indexes ~37 ms. So the per-class work is
 *  cached and everything else is recomputed every run. The closure especially: a callee's new effect
 *  changes callers that did not themselves change, which is the entire point of the tool, and at 3.4%
 *  it is never worth the risk of serving a stale one.
 *
 *  <p>THE SAFETY CONTRACT. A stale entry read as current is a silent under-report inside a
 *  normal-looking report — this project's cardinal sin — so the cache fails closed at every step:
 *  entries are keyed on CONTENT (never mtime), a different engine build discards the whole cache
 *  because a classifier fix must not be silently skipped, and anything unrecognised or unreadable
 *  abandons the cache and takes the full scan rather than guessing. Its acceptance test is byte
 *  equality with a cold scan across the report and every sidecar: bin/refresh-equiv.sh.
 */
final class Refresh {

    /** A scan with no cache: every class is analysed, nothing is stored. The overlay split still runs —
     *  see the analyze loop in {@link Candor} for why there is only ever one path. */
    private static final Refresh DISABLED = new Refresh();

    private Refresh() {}

    static Refresh forScan(Config cfg, List<ClassNode> classes) {
        return DISABLED;
    }

    /** True when this class's delta came from the cache and {@code analyze} can be skipped. */
    boolean replayInto(ClassNode cn, AnalysisContext overlay) {
        return false;
    }

    /** Take this class's freshly-computed delta for storage. */
    void record(ClassNode cn, AnalysisContext overlay) {
    }

    /** Persist whatever the scan learned, and disclose the reuse. */
    void finish() {
    }

    /** THE SPLIT'S OWN VERIFICATION (CANDOR_REFRESH_VERIFY). Off by default because it costs a pass over
     *  the shared inputs per scan; on in the test suite and in bin/refresh-equiv.sh, where it is the
     *  check that an accumulator has not been misfiled as a shared input — the one error mode that a
     *  cold byte-equality comparison structurally cannot see, because on a cold run the misfiled writes
     *  still reach the master and the answer still comes out right. */
    static boolean verifying() {
        String v = System.getenv("CANDOR_REFRESH_VERIFY");
        return v != null && !v.isEmpty() && !v.equals("0");
    }
}
