package io.poly.candor;

/** The handle to the engine's per-scan state. The mutable fields live on {@link AnalysisContext} (an
 *  instance); the engine reaches them as {@code ctx().<field>} via this statically-imported accessor.
 *
 *  <p>LB-1b: the context is held in a {@link ThreadLocal}, so each scanning thread owns its own state.
 *  A single static field would be globally aliased — two concurrent scans would clobber each other (not
 *  re-entrant). With a per-thread context, parallel scans (multi-jar, or candor embedded behind a
 *  request-per-thread server) are isolated. {@link Candor#resetState()} starts a fresh context for the
 *  current thread at the top of each scan. See docs/level-b-scoping.md. */
final class AnalysisState {
    private AnalysisState() {}

    private static final ThreadLocal<AnalysisContext> TL = ThreadLocal.withInitial(AnalysisContext::new);

    /** The current thread's scan state. */
    static AnalysisContext ctx() {
        return TL.get();
    }

    /** Start a fresh context for the current thread (the per-scan reset; also frees the prior scan's
     *  state on a thread that runs several scans in sequence). */
    static void newContext() {
        TL.set(new AnalysisContext());
    }
}
