package io.poly.candor.nativeparity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

/**
 * THE ARM THAT ONLY {@code candor/jdk-generics.idx.gz} CAN ANSWER — SOUNDNESS R1461.
 *
 * <p>{@code genArm} iterates a {@code Collection<Integer>}; the program's only project {@code Iterator} is an
 * {@code Iterator<String>}. Proving the pair incompatible needs the generic signatures of
 * {@code Collection.iterator()} and of {@code Iterator}, which the engine reads from the bundled index on the jar and
 * the native image alike. With the index the edge is demoted and the row discloses
 * {@code Unknown / dispatch:java.util.Iterator.next}; without it the edge is kept and the row carries {@code Fs} and no
 * such reason.
 *
 * <p>The disclosure covers a real write: {@link Drive} hands {@code genArm} a {@link RawInts}, whose RAW
 * {@code iterator()} override returns the {@code Iterator<String>} — heap pollution the JVM does not stop, which is why
 * the edge is hedged rather than dropped.
 */
public final class GenArm {
    private GenArm() { }

    /** The project's only Iterator: an Iterator&lt;String&gt; whose next() performs the effect. */
    public static final class StrIter implements Iterator<String> {
        private boolean done;
        @Override public boolean hasNext() { return !done; }
        @Override public String next() {
            done = true;
            Eff.bump();
            return "x";
        }
    }

    /** A {@code List<Integer>} whose raw iterator is the String one (compiles with an unchecked warning). */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static final class RawInts extends ArrayList<Integer> {
        private static final long serialVersionUID = 1L;
        @Override public Iterator iterator() { return new StrIter(); }
    }

    /** Iterates without touching the element's type, so the polluted run completes (no CCE). */
    public static int genArm(Collection<Integer> c) {
        int n = 0;
        for (Object x : c) n++;
        return n;
    }
}
