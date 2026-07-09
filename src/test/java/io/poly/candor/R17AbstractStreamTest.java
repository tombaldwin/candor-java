package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * R17 (SOUNDNESS.md §5) — the abstract-{@code java.io}-stream boundary. A rooted ENTRY POINT that reads
 * its OWN abstract stream parameter (framework-injected; concrete impl unresolvable) used to read
 * silent-pure. The provenance-gated fix discloses {@code Unknown} for exactly that case, while NOT
 * flooding internal helpers that read a passed stream (whose in-project caller holds the concrete).
 */
class R17AbstractStreamTest {

    @Test
    void entryPointReadingItsAbstractStreamParamDisclosesUnknownWithoutFlooding() throws Exception {
        Path cls = compile(Map.of(
            // A framework annotation candor roots (@Subscribe), at its real FQN with RUNTIME retention.
            "com/google/common/eventbus/Subscribe.java",
            "package com.google.common.eventbus; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Subscribe {}",
            "app/R17.java",
            "package app; import java.io.*; import com.google.common.eventbus.Subscribe; public class R17 {"
                + " @Subscribe void onData(InputStream s) throws IOException { s.readAllBytes(); }"   // entry reads abstract param
                + " void helper(InputStream s) throws IOException { s.read(); }"                       // non-entry -> must stay pure
                + " void use() throws IOException { helper(new FileInputStream(\"/tmp/x\")); }"        // caller has concrete -> Fs
                + " void readsOwnFile() throws IOException { new FileInputStream(\"/tmp/x\").read(); } }")); // concrete -> Fs
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);

            // The fix: a rooted entry point reading its OWN abstract stream param discloses Unknown.
            assertTrue(r.getOrDefault("app.R17.onData", EffectSet.empty()).toNames().contains("Unknown"),
                    "entry point reading its abstract InputStream param must disclose Unknown (R17), not read pure");

            // No flood: a NON-entry helper reading a passed abstract stream stays pure (its caller holds the
            // concrete, so the effect is attributed at the creation site, not here).
            assertFalse(r.getOrDefault("app.R17.helper", EffectSet.empty()).toNames().contains("Unknown"),
                    "internal helper reading a passed stream must NOT be flooded with Unknown");
            assertTrue(r.getOrDefault("app.R17.helper", EffectSet.empty()).isEmpty(),
                    "internal helper reading a passed stream stays pure (R17 is entry-point-gated)");

            // The common case is unchanged: an in-scope concrete creation is attributed Fs at the creator.
            assertTrue(r.getOrDefault("app.R17.use", EffectSet.empty()).toNames().contains("Fs"),
                    "the caller that creates the concrete FileInputStream carries Fs");
            assertTrue(r.getOrDefault("app.R17.readsOwnFile", EffectSet.empty()).toNames().contains("Fs"),
                    "a method that creates + reads a concrete stream carries Fs (unchanged)");
        } finally {
            rm(cls.getParent());
        }
    }
}
