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

    /** Install a specific context on the current thread. The refresh analyses one class at a time into
     *  an OVERLAY (see {@link AnalysisContext}'s overlay constructor) and needs that overlay to be what
     *  {@code ctx()} returns for the duration — including inside the helpers that reach the context
     *  statically rather than through a parameter. Installing it is what makes those reads impossible to
     *  miss: threading a parameter through instead would cover only the call sites someone remembered to
     *  change, and one helper still reaching the master would write a class's effects somewhere that
     *  class's delta cannot see them — which is the silent under-report the whole split is arranged
     *  to prevent. */
    static void install(AnalysisContext c) {
        TL.set(c);
    }

    /** Release the current thread's context once a scan's outputs are fully written. A {@link ThreadLocal}
     *  that is only ever {@code set} pins the last scan's whole state (call graph + every ClassNode) for
     *  the thread's lifetime — a retention leak on a pooled/long-lived thread (the {@code --parallel} pool,
     *  or candor embedded behind a request-per-thread server). Callers that own the thread should call this
     *  in a {@code finally} after the report is written. */
    static void remove() {
        TL.remove();
    }
}
