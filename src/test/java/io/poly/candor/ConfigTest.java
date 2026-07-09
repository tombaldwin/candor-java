package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * `.candor/config` — the checked-in alternative to the CANDOR_* env vars. Covers the §6.2-style line
 * parsing, the config-value path, boolean flags, the deps path-list, and the precedence contract (env
 * OVERRIDES config — tested via an env var that is guaranteed UNSET, so `value` falls through to the file;
 * the env-present branch is exercised end-to-end by the CLI/manual runs, since Java can't set env in-JVM).
 */
class ConfigTest {

    private static final String UNSET = "CANDOR_DEFINITELY_UNSET_ENV_ZZZ";

    private static Path lastConfigPath;

    private static Config write(String body) throws Exception {
        Path p = Files.createTempFile("candor-config", "");
        Files.writeString(p, body);
        p.toFile().deleteOnExit();
        lastConfigPath = p;
        return Config.load(p);
    }

    /** What a relative path VALUE in the last-written config resolves to (its anchor — here the config
     *  file's own directory: a plain temp file has no {@code .candor/} parent to step out of). */
    private static String anchored(String rel) {
        return Config.anchorFor(lastConfigPath).resolve(rel).normalize().toString();
    }

    @Test
    void parsesKeyValueLinesWithCommentsAndBlanks() throws Exception {
        Config c = write("""
            # a checked-in config
            policy    arch.policy       # inline comment stripped
            baseline  .candor/base.json

            strict    com.acme.domain
            """);
        // path values are ANCHOR-resolved (against the config, never the CWD) — the family rule.
        assertEquals(anchored("arch.policy"), c.value("policy", UNSET), "config value used when the env var is unset");
        assertEquals(anchored(".candor/base.json"), c.value("baseline", UNSET));
        assertEquals("com.acme.domain", c.value("strict", UNSET), "a scope value keeps its content — not a path key");
    }

    @Test
    void relativePathsAnchorToTheDirectoryHoldingDotCandor() throws Exception {
        // The family anchor semantics (swift/ts/agents parity): a config at <root>/.candor/config anchors
        // relative values at <root> — the repo root the config travels with — so `policy .candor/gate.pol`
        // is <root>/.candor/gate.pol and `baseline arch/base.json` is <root>/arch/base.json, wherever the
        // process was launched. An absolute value is untouched.
        Path root = Files.createTempDirectory("candor-anchor");
        Path cfg = Files.createDirectories(root.resolve(".candor")).resolve("config");
        Files.writeString(cfg, "policy .candor/gate.pol\nbaseline arch/base.json\n");
        Config c = Config.load(cfg);
        Path anchor = Config.anchorFor(cfg);
        assertEquals(root.toAbsolutePath().normalize(), anchor, "anchorFor steps the trailing .candor segment out");
        assertEquals(anchor.resolve(".candor/gate.pol").toString(), c.value("policy", UNSET),
                "resolves against the dir HOLDING .candor/, not the config file's own dir");
        assertEquals(anchor.resolve("arch/base.json").toString(), c.value("baseline", UNSET));
        Files.writeString(cfg, "policy /abs/gate.pol\n");
        assertEquals("/abs/gate.pol", Config.load(cfg).value("policy", UNSET), "an absolute value is untouched");
    }

    @Test
    void outOfTreeConfigAnchorsToItsOwnDirectory() throws Exception {
        // A CANDOR_CONFIG override file living anywhere (not inside a .candor/) anchors at its own dir.
        Path dir = Files.createTempDirectory("candor-oot");
        Path cfg = dir.resolve("shared.config");
        Files.writeString(cfg, "policy gate.pol\n");
        assertEquals(dir.toRealPath(), Config.anchorFor(cfg).toRealPath());
        assertEquals(Config.anchorFor(cfg).resolve("gate.pol").toString(),
                Config.load(cfg).value("policy", UNSET));
    }

    @Test
    void missingKeyAndMissingFileAreNull() throws Exception {
        assertNull(write("policy arch.policy\n").value("baseline", UNSET), "an absent key → null");
        assertNull(Config.load(Path.of("/no/such/.candor/config")).value("policy", UNSET), "a missing file → empty");
    }

    @Test
    void anUnknownKeyIsWarnedAndIgnoredNeverConsumed() throws Exception {
        // Typo protection (the cross-engine §config rule): `polcy arch.policy` must not silently become
        // a dropped gate — the key is warned about and never enters the map.
        Config c = write("polcy arch.policy\npolicy real.policy\n");
        assertNull(c.value("polcy", UNSET), "the unknown key never enters the map");
        assertEquals(anchored("real.policy"), c.value("policy", UNSET), "the valid line still parses");
    }

    @Test
    void aBareValueKeyIsEnabledWithTheEmptyValue() throws Exception {
        // A lone `strict` line means "enabled, empty value" — the set-but-empty env analog (whole-unit
        // scope). Mapping it to null silently DISABLED the gate the user just configured (review find).
        assertEquals("", write("strict\n").value("strict", UNSET), "bare key → \"\" (enabled), never null");
        assertEquals("", write("no-ambient   # whole repo\n").value("no-ambient", UNSET));
        assertNull(write("policy p\n").value("strict", UNSET), "absent stays null — the distinction is load-bearing");
    }

    @Test
    void booleanFlagsAreTruthyOrBareKey() throws Exception {
        assertTrue(write("closed-world true\n").flag("closed-world", UNSET));
        assertTrue(write("closed-world\n").flag("closed-world", UNSET), "a bare key (no value) means on");
        assertTrue(write("taint yes\n").flag("taint", UNSET));
        assertFalse(write("closed-world false\n").flag("closed-world", UNSET), "explicit false is off");
        assertFalse(write("policy p\n").flag("closed-world", UNSET), "an absent flag is off");
    }

    @Test
    void depsBecomeAPathList() throws Exception {
        // a whitespace-separated list in the file → the OS-path-separated DEPS form loadCrossDeps
        // consumes, EACH element anchor-resolved (so `../a/…` means "next to the config's repo", not
        // "next to wherever CI happened to launch the JVM").
        Config c = write("deps  ../a/.candor/report.json   ../b/.candor/report.json\n");
        assertEquals(anchored("../a/.candor/report.json") + File.pathSeparator + anchored("../b/.candor/report.json"),
                c.value("deps", UNSET));
    }

    @Test
    void envOverridesTheConfigFile() throws Exception {
        // The precedence contract, tested at the seam we CAN control: an env var that IS set (PATH exists on
        // every runner) wins over the config file's value. (The value is PATH's, not "x" — env overrode.)
        Config c = write("path-probe should-not-win\n");   // arbitrary key mapped to a real env var below
        String viaEnv = c.value("path-probe", "PATH");
        assertEquals(System.getenv("PATH"), viaEnv, "a SET env var overrides the config file");
        assertFalse("should-not-win".equals(viaEnv));
    }
}
