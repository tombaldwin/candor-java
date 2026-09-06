package io.poly.candor.nativeparity;

import java.util.Optional;

/**
 * §E3 — GROUND TRUTH EXECUTED. Every arm of this fixture is RUN here, and each performs exactly one
 * append to the witness file, so {@code ci/native-parity-selftest.sh} can prove the program really does
 * what the marker rows in {@code ci/native-parity.py} say it does BEFORE it believes anything about a
 * row's absence. Five arms, five appends.
 *
 * <p>Never run by the parity SCAN — candor reads bytecode, it does not execute the target. This exists
 * so a fixture that silently stopped performing its effect could not go on reading as coverage.
 */
public final class Drive {
    private Drive() { }

    /** @param args ignored. */
    public static void main(String[] args) {
        HofArm.hofOrElseGet(Optional.empty(), () -> {
            Eff.bump();
            return "x";
        });
        HofArm.hofRequireNonNullElseGet(null, () -> {
            Eff.bump();
            return "x";
        });
        SamArm sam = new SamArm();
        sam.samInstall();
        sam.samViaIterable();
        SuperArm.superWalkList(new SuperArm.EffList());
        SuperArm.superWalkMap(new SuperArm.EffMap());
    }
}
