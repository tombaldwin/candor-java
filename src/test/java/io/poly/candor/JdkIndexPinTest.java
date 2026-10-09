package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1094 — the three derived JDK indexes are PINNED INPUTS, not a property of the JDK that ran the build.
 *
 * <p>Before R1094 {@code build.gradle.kts} wrote them from {@code jrt:/} of the Gradle daemon's JVM, and the published
 * v0.40.3 jar carried a Corretto 17.0.14 derivation while a JDK 21 build of the same commit carried another. Now
 * {@code soundness/jdk_index/derive.sh} writes them from the Temurin images pinned in {@code images.tsv}, records each
 * index's decompressed content hash and a generator hash in {@code manifest.txt}, and the build copies the files.
 * This test is the per-push half (the half that needs the images is {@code derive.sh --check}):
 * <ul>
 *   <li>each checked-in index decompresses to the content its manifest line hashes (a hand edit fails here);
 *   <li>the generator inputs hash to the manifest's {@code generator-sha256} (a generator change not followed by a
 *       regeneration fails here);
 *   <li>the resource the ENGINE loads from its classpath is byte-for-byte the checked-in file (a build step that
 *       regenerated or rewrote it fails here);
 *   <li>the build script derives nothing from the JDK it runs on ({@code jrt:/} does not appear in it outside comments).
 * </ul>
 */
class JdkIndexPinTest {

    static final Path ROOT = Path.of(System.getProperty("user.dir"));
    static final Path DIR = ROOT.resolve("soundness/jdk_index");
    static final List<String> INDEXES = List.of("jdk-supertypes.idx", "jdk-sams.idx", "jdk-hof-invokes.idx", "jdk-functional.idx");

    static String sha(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    static Map<String, String[]> manifest() throws Exception {
        Map<String, String[]> m = new HashMap<>();
        for (String l : Files.readAllLines(DIR.resolve("manifest.txt"), StandardCharsets.UTF_8)) {
            if (l.isBlank() || l.startsWith("#")) continue;
            String[] p = l.split(" ");
            m.put(p[0], p);
        }
        return m;
    }

    static byte[] gunzip(InputStream in) throws Exception {
        try (var g = new GZIPInputStream(in)) { return g.readAllBytes(); }
    }

    @Test
    void eachCheckedInIndexIsWhatItsManifestLineHashes() throws Exception {
        Map<String, String[]> m = manifest();
        for (String f : INDEXES) {
            Path p = ROOT.resolve("src/main/resources/candor/" + f + ".gz");
            assertTrue(Files.isRegularFile(p), f + ".gz must be checked in under src/main/resources/candor");
            byte[] text = gunzip(Files.newInputStream(p));
            String[] line = m.get(f);
            assertNotNull(line, "manifest.txt has no line for " + f);
            assertEquals(line[1], sha(text), f + " does not hash to manifest.txt — it was edited by hand, or regenerated "
                    + "without its manifest. Rerun `bash soundness/jdk_index/derive.sh` and read the diff.");
            long lines = new String(text, StandardCharsets.UTF_8).lines().count();
            assertEquals(Long.parseLong(line[2]), lines, f + " line count");
            assertTrue(lines > 100, f + " is implausibly small (" + lines + " lines) — an empty index passes every hash");
        }
    }

    @Test
    void theGeneratorInputsHashToTheManifest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (String f : List.of("JdkIndexGen.java", "derive.sh", "images.tsv", "asm.tsv")) md.update(Files.readAllBytes(DIR.resolve(f)));
        assertEquals(manifest().get("generator-sha256")[1], HexFormat.of().formatHex(md.digest()),
                "the generator or its pinned inputs changed and the indexes were not regenerated: run "
                        + "`bash soundness/jdk_index/derive.sh`");
    }

    @Test
    void theEngineLoadsExactlyTheCheckedInBytes() throws Exception {
        for (String f : INDEXES) {
            byte[] onDisk = Files.readAllBytes(ROOT.resolve("src/main/resources/candor/" + f + ".gz"));
            try (InputStream in = Candor.class.getResourceAsStream("/candor/" + f + ".gz")) {
                assertNotNull(in, f + ".gz is not on the engine's classpath");
                assertArrayEquals(onDisk, in.readAllBytes(), f + ".gz on the classpath is not the checked-in file — "
                        + "something in the build rewrote it");
            }
        }
    }

    @Test
    void theBuildDerivesNothingFromTheJdkItRunsOn() throws Exception {
        for (String l : Files.readAllLines(ROOT.resolve("build.gradle.kts"), StandardCharsets.UTF_8)) {
            String code = l.contains("//") ? l.substring(0, l.indexOf("//")) : l;
            assertFalse(code.contains("jrt:/") || code.contains("jrt:"),
                    "build.gradle.kts reads jrt:/ again — a resource derived from the daemon's JDK is R1094: " + l.strip());
        }
    }

    /** The R1092 facts the union exists for: JDK 25 SAMs and invoking HOFs are present (a JDK 21-only derivation lacks
     *  them), and a JDK 17-era fact the published jar carried is still present. */
    @Test
    void theUnionCarriesJdk25AndJdk17Facts() throws Exception {
        String sams = new String(gunzip(Files.newInputStream(ROOT.resolve("src/main/resources/candor/jdk-sams.idx.gz"))), StandardCharsets.UTF_8);
        String hof = new String(gunzip(Files.newInputStream(ROOT.resolve("src/main/resources/candor/jdk-hof-invokes.idx.gz"))), StandardCharsets.UTF_8);
        assertTrue(sams.contains("java/lang/ScopedValue$CallableOp call\n"), "JDK 25 SAM ScopedValue.CallableOp");
        assertTrue(hof.contains("call (Ljava/lang/ScopedValue$CallableOp;)Ljava/lang/Object; 0"), "JDK 25 HOF Carrier.call(CallableOp)");
        assertTrue(sams.contains("jdk/incubator/foreign/SymbolLookup lookup\n"), "a JDK 17-only SAM the published jar carried");
    }
}
