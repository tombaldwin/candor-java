package io.poly.candor;

/** The handle to the engine's per-scan state. LB-0: the mutable fields moved to {@link AnalysisContext}
 *  (an instance); the engine reaches them as {@code ctx.<field>} via this statically-imported handle, so
 *  behavior is unchanged (still one process-global context). LB-1 will remove this handle and thread an
 *  {@code AnalysisContext} per scan, making the engine re-entrant. See docs/level-b-scoping.md. */
final class AnalysisState {
    private AnalysisState() {}

    /** The current scan's state. {@code Candor.resetState()} replaces it with a fresh instance. */
    static AnalysisContext ctx = new AnalysisContext();
}
