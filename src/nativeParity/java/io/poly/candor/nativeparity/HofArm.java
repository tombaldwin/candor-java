package io.poly.candor.nativeparity;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * THE ARM THAT ONLY {@code candor/jdk-hof-invokes.idx.gz} CAN ANSWER — SOUNDNESS R237.
 *
 * <p>Both callbacks arrive as PARAMETERS and no class in this fixture implements {@code Supplier}, so
 * CHA has nothing to resolve and a disclosure is the only honest answer. {@code Optional.orElseGet} and
 * {@code Objects.requireNonNullElseGet} are not in {@code Candor.isInvokingHof}'s hand-written name list,
 * so the ONLY thing that turns them into
 * {@code Unknown / callback:java.util.function.Supplier.get} is the swept index.
 *
 * <p>MEASURED, not assumed: with {@code candor/jdk-hof-invokes.idx.gz} stripped from the scanning jar,
 * both rows leave {@code functions[]} ENTIRELY — the silent-under-report shape. That is what
 * {@code ci/native-parity.py}'s marker control keys on, and {@code ci/native-parity-selftest.sh} proves
 * the control red on a stripped jar and green on a whole one.
 */
public final class HofArm {
    private HofArm() { }

    /** {@code Optional.orElseGet} really invokes its supplier — {@link Drive} runs this arm. */
    public static String hofOrElseGet(Optional<String> o, Supplier<String> s) {
        return o.orElseGet(s);
    }

    /** {@code Objects.requireNonNullElseGet} reaches its supplier through an identity wrapper AND a
     *  CHECKCAST, which is why the sweep has to see through both. */
    public static String hofRequireNonNullElseGet(String x, Supplier<String> s) {
        return Objects.requireNonNullElseGet(x, s);
    }
}
