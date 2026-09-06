package io.poly.candor.nativeparity;

import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * THE ARM THAT ONLY {@code candor/jdk-supertypes.idx.gz} CAN ANSWER — and the one whose teeth exist ONLY
 * ON THE NATIVE LEG.
 *
 * <p>{@code Cha.externalSupers} reads a JDK class's supers with {@code ClassReader} off candor's own
 * classpath, and consults the bundled index ONLY when that read throws — which on the JVM it never does,
 * so {@code Cha.JdkSupers} is gated behind {@code IN_NATIVE_IMAGE} and is never even loaded from the jar.
 * A native image has no {@code .class} files, so there the index is the only answer.
 *
 * <p>{@code EffList}'s only route to {@code java.util.List} runs through {@code java.util.AbstractList},
 * which is EXTERNAL — so registering {@code EffList} as a subtype of {@code List} requires resolving an
 * external class's supers. Without the index a native binary stops at {@code AbstractList}, CHA never
 * offers {@code EffList.get} at the {@code l.get(0)} call site, and {@code superWalkList} loses its
 * {@code Fs} — absent from {@code functions[]} entirely, which is the cardinal-sin signature.
 *
 * <p>MEASURED (2026-09-06, R249) rather than reasoned: a throwaway worktree jar patched to force
 * {@code ClassReader} to throw for every external name — the native image's real condition — reports
 * {@code superWalkList} and {@code superWalkMap} identically to the jar WITH the index bundled, and
 * loses both rows WITHOUT it. Nothing else in the fixture moved either way. That patch is not in this
 * repo and cannot be: the local half of this gate is
 * {@code ./gradlew verifyNativeImageResources}, which catches a dropped
 * {@code -H:IncludeResources} line without GraalVM; this arm's teeth are CI-only.
 */
public final class SuperArm {
    private SuperArm() { }

    /** A project class whose route to {@code java.util.List} is through an EXTERNAL abstract class. */
    public static final class EffList extends AbstractList<String> {
        @Override public String get(int i) {
            Eff.bump();
            return "x";
        }

        @Override public int size() {
            return 1;
        }
    }

    /** The same shape one hierarchy over — {@code AbstractMap} rather than {@code AbstractList} — so a
     *  single missing index entry cannot be mistaken for a whole missing index. */
    public static final class EffMap extends AbstractMap<String, String> {
        @Override public Set<Map.Entry<String, String>> entrySet() {
            Eff.bump();
            return Set.of();
        }
    }

    /** Dispatches through {@code java.util.List}, which {@code EffList} only reaches externally. */
    public static String superWalkList(List<String> l) {
        return l.get(0);
    }

    /** Dispatches through {@code java.util.Map}, which {@code EffMap} only reaches externally. */
    public static Set<Map.Entry<String, String>> superWalkMap(Map<String, String> m) {
        return m.entrySet();
    }
}
