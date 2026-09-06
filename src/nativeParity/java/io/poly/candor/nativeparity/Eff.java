package io.poly.candor.nativeparity;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * The one effect every arm of the native-parity fixture performs: an append to the file named by
 * {@code candor.nativeparity.witness}. {@code Fs} is the effect the report must carry, and the write is
 * REAL — {@code ci/native-parity-selftest.sh} runs {@link Drive} and counts the appends before it
 * believes any row below, because an omitted pure method and an omitted effectful one are the same
 * bytes (corpus brief §E3).
 *
 * <p>The path comes from a property the caller sets to a directory IT created. Nothing here deletes
 * anything: a test in this repo once cleaned up {@code cls.getParent().getParent()} and took the system
 * temp directory with it.
 */
public final class Eff {
    private Eff() { }

    /** One append. Returns an int so it can be a {@code IntSupplier}/{@code ToIntFunction} target too. */
    public static int bump() {
        String w = System.getProperty("candor.nativeparity.witness");
        if (w == null) return 0;
        try {
            Files.writeString(Paths.get(w), "x", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        return 1;
    }
}
