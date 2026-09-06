package io.poly.candor.nativeparity;

import java.util.ArrayList;
import java.util.List;

/**
 * THE ARM THAT ONLY {@code candor/jdk-sams.idx.gz} CAN ANSWER — SOUNDNESS R191.
 *
 * <p>THE INTERFACE HAD TO BE {@code java.lang.Iterable}, AND THAT IS A MEASUREMENT, NOT A PREFERENCE.
 * The obvious R191 spelling — {@code IntSupplier::getAsInt} handed to {@code forEach} — is NOT sensitive
 * to this index: {@code Candor.isJdkFunctionalSam} short-circuits every {@code java/util/function/} owner
 * through the hand-written {@code FUNCTION_PKG_SAM} name set, so the row discloses with the index
 * stripped. {@code java.util.Comparator} is no better — it is one of the eighteen entries in
 * {@code Candor.SAM_OF}, which {@code samNameOf} consults before the index. {@code Iterable} is in
 * neither, so {@code samNameOf} can only answer it from the index; stripping the resource removes this
 * row from {@code functions[]} entirely, and nothing else in the fixture moves.
 *
 * <p>It is also the sibling R191 was NOT handed (corpus brief §A.2): the row was written about
 * {@code java.util.function}, and {@code Iterable::iterator} is the shape guava, ant and
 * spring-data-commons actually contain.
 */
public final class SamArm {

    private final List<Iterable<String>> iters = new ArrayList<>();

    /** Installs a callback that really performs the effect, so the row below is about a program that
     *  does what this class says it does. */
    public void samInstall() {
        iters.add(() -> {
            Eff.bump();
            return List.<String>of().iterator();
        });
    }

    /** {@code Iterable::iterator} names an ABSTRACT method, so the body that runs belongs to whatever
     *  receiver {@code forEach} supplies — {@code Unknown / callback:java.lang.Iterable.iterator}, and
     *  only if {@code samNameOf} can name {@code iterator} as {@code Iterable}'s SAM. */
    public void samViaIterable() {
        iters.forEach(Iterable::iterator);
    }
}
