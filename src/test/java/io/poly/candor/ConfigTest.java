package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * `.candor/config` — the checked-in alternative to the CANDOR_* env vars. Covers the §6.2-style line
 * parsing, the config-value path, boolean flags, the deps path-list, and the precedence contract (env
 * OVERRIDES config — tested via an env var that is guaranteed UNSET, so `value` falls through to the file;
 * the env-present branch is exercised end-to-end by the CLI/manual runs, since Java can't set env in-JVM).
 */
class ConfigTest {

    @TempDir
    Path tmp;

    private static final String UNSET = "CANDOR_DEFINITELY_UNSET_ENV_ZZZ";

    private static Path lastConfigPath;

    private Config write(String body) throws Exception {
        Path p = Files.createTempFile(tmp, "candor-config", "");
        Files.writeString(p, body);
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
        Path root = Files.createTempDirectory(tmp, "candor-anchor");
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
        Path dir = Files.createTempDirectory(tmp, "candor-oot");
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

    @Test
    void unknownAliasIsMultiValueAndRejectsReservedNames() throws Exception {
        // ⟨0.19⟩ SPEC §6.2: `unknown-alias <name> = <class,…>` — many names (a multi-value key), a name
        // shadowing a class token / `dynamic` / `*` is rejected, `dynamic` expands, an invalid class is dropped.
        Config c = write("""
            unknown-alias risky = reflect,native
            unknown-alias broad = dynamic
            unknown-alias reflect = native
            unknown-alias empty = nope
            """);
        var a = c.unknownAliases();
        assertEquals(java.util.EnumSet.of(io.poly.candor.model.ReasonClass.REFLECT, io.poly.candor.model.ReasonClass.NATIVE), a.get("risky"));
        assertEquals(io.poly.candor.model.ReasonClass.dynamicSet(), a.get("broad"), "`dynamic` expands to every genuine class");
        assertNull(a.get("reflect"), "a config alias may not shadow a class token");
        assertNull(a.get("empty"), "an alias naming no valid class is dropped");
    }

    // ── SPEC §3.4 `engine` — the engine↔baseline coupling ────────────────────────────────────────────
    // The pin exists because a newer engine resolves more dispatch, so its report is not comparable with
    // a baseline the pinned engine wrote — and until now nothing enforced "regenerate the baseline when
    // you bump the engine". Every branch is asserted through the PURE verdict rather than the printing
    // enforcement site, because the two verdicts that matter most are the ones that must NOT exit.

    @Test
    void enginePinParsesBothTheQualifiedAndUnqualifiedForms() throws Exception {
        Config c = write("""
            # the family releases on a LADDER, so a polyglot repo pins per implementation
            engine rust v0.26.0
            engine java v0.27.0
            """);
        assertEquals("v0.27.0", c.enginePinForThisEngine(), "the java-qualified pin is the one that applies");
        assertEquals("v0.26.0", c.enginePins().get("rust"));

        Config bare = write("engine v0.27.0\n");
        assertEquals("v0.27.0", bare.enginePinForThisEngine(), "an unqualified pin applies to whichever engine reads it");
    }

    @Test
    void aQualifiedPinForAnotherEngineIsNotOursToCheck() throws Exception {
        // One config serves the whole family. candor-java must not fail a run because the SWIFT pin is
        // stale — that is candor-swift's to enforce when candor-swift reads this same file.
        Config c = write("engine swift v0.26.0\n");
        assertNull(c.enginePinForThisEngine());
        assertEquals(Config.PinVerdict.ABSENT, Config.pinVerdict(c.enginePinForThisEngine(), "0.27.0"));
    }

    @Test
    void aQualifiedPinWinsOverTheUnqualifiedOne() throws Exception {
        Config c = write("""
            engine v0.20.0
            engine java v0.27.0
            """);
        assertEquals(Config.PinVerdict.MATCH, Config.pinVerdict(c.enginePinForThisEngine(), "0.27.0"),
                "the specific pin decides; the wildcard is the fallback");
    }

    @Test
    void theTagAndJarFilenameSpellingsAreTheSamePin() {
        // `v0.27.0` is the GitHub tag, `0.27.0` is the jar filename. A consumer copies whichever is in
        // front of them, and being told those disagree would be a defect in the check, not in the repo.
        assertEquals(Config.PinVerdict.MATCH, Config.pinVerdict("v0.27.0", "0.27.0"));
        assertEquals(Config.PinVerdict.MATCH, Config.pinVerdict("0.27.0", "0.27.0"));
        assertEquals(Config.PinVerdict.MATCH, Config.pinVerdict("0.27", "0.27.0"), "a two-part pin means .0");
    }

    @Test
    void aDifferentEngineVersionIsAMismatch() {
        assertEquals(Config.PinVerdict.MISMATCH, Config.pinVerdict("v0.26.0", "0.27.0"));
        assertEquals(Config.PinVerdict.MISMATCH, Config.pinVerdict("v0.27.1", "0.27.0"), "patch versions differ too");
    }

    @Test
    void anUnreadablePinIsMalformedRatherThanAMismatchThatNeverMatches() {
        // The distinction decides which sentence the operator reads: "wrong version" sends them to the
        // pin, "that is not a version" sends them to the spelling. `latest` is the one a human writes.
        assertEquals(Config.PinVerdict.MALFORMED, Config.pinVerdict("latest", "0.27.0"));
        assertEquals(Config.PinVerdict.MALFORMED, Config.pinVerdict("", "0.27.0"), "a bare `engine` line");
        assertEquals(Config.PinVerdict.MALFORMED, Config.pinVerdict("main", "0.27.0"));
    }

    @Test
    void aMalformedPinIsRecordedNotDroppedAsAnUnparsedLine() throws Exception {
        // THE FAILURE MODE THIS GUARDS. Every other malformed line in this file warns and skips, which is
        // right for a key that ADDS something. Here, skipping would hand the enforcement site ABSENT — and
        // ABSENT passes. A pin the operator cannot spell would become a guard they believe is on and is not.
        assertEquals("latest", write("engine latest\n").enginePinForThisEngine());
        assertEquals("", write("engine\n").enginePinForThisEngine(), "a bare `engine` line is recorded, not skipped");
        // And the shape that keyed the map on the VERSION, filing the pin under an implementation named
        // `0.26.0` where this engine never looks — silently switching the pin off.
        assertEquals(Config.PinVerdict.MALFORMED,
                Config.pinVerdict(write("engine 0.26.0 oops\n").enginePinForThisEngine(), "0.27.0"));
        assertEquals(Config.PinVerdict.MALFORMED,
                Config.pinVerdict(write("engine java\n").enginePinForThisEngine(), "0.27.0"),
                "an impl name with no version");
    }

    @Test
    void twoEngineLinesThatDisagreeAreMALFORMED_notLastWins() throws Exception {
        // Found by adversarial review. `Map.put` meant last-wins SILENTLY: the operator wrote 0.26.0,
        // the file also said 0.27.0, and the run exited 0 MATCH having discarded the first. A pin the
        // operator wrote being thrown away without a word is the failure class this key exists to stop,
        // which is why it does NOT follow the file's ordinary last-wins convention. Two lines disagreeing
        // about which engine to run is not a preference to resolve; it is a question the config leaves
        // unanswered — so it fails, quoting both spellings back.
        Config c = write("engine java 0.26.0\nengine java 0.27.0\n");
        assertEquals(Config.PinVerdict.MALFORMED, Config.pinVerdict(c.enginePinForThisEngine(), "0.27.0"));
        assertTrue(c.enginePinForThisEngine().contains("0.26.0")
                && c.enginePinForThisEngine().contains("0.27.0"), "both lines are shown: " + c.enginePinForThisEngine());
        // An IDENTICAL repeat is harmless — it states the same thing twice and answers the question.
        Config same = write("engine v0.27.0\nengine v0.27.0\n");
        assertEquals(Config.PinVerdict.MATCH, Config.pinVerdict(same.enginePinForThisEngine(), "0.27.0"));
        // …and a conflict between the QUALIFIED and UNQUALIFIED forms is not a conflict at all: §3.4
        // says the qualified pin wins, so this stays a legitimate polyglot config.
        Config mixed = write("engine v0.20.0\nengine java v0.27.0\n");
        assertEquals(Config.PinVerdict.MATCH, Config.pinVerdict(mixed.enginePinForThisEngine(), "0.27.0"));
    }

    @Test
    void trailingJunkIsMALFORMED_inTheQualifiedFormToo() throws Exception {
        // One grammar, two answers: `engine 0.26.0 0.27.0` correctly refused while
        // `engine java 0.26.0 0.27.0` took parts[1] and silently pinned 0.26.0 — the qualified arm was
        // the forgiving one, on the half where a second version is most obviously a mistake.
        assertEquals(Config.PinVerdict.MALFORMED,
                Config.pinVerdict(write("engine java 0.26.0 0.27.0\n").enginePinForThisEngine(), "0.27.0"));
        assertEquals(Config.PinVerdict.MALFORMED,
                Config.pinVerdict(write("engine java 0.27.0 junk\n").enginePinForThisEngine(), "0.27.0"));
        // The good qualified form still works.
        assertEquals(Config.PinVerdict.MATCH,
                Config.pinVerdict(write("engine java v0.27.0\n").enginePinForThisEngine(), "0.27.0"));
    }

    @Test
    void aSourceBuildCannotCheckThePinAndMustNotScoreIt() {
        // ⟨0.24⟩ §3.1 applied to configuration: an UNANSWERABLE condition is disclosed, never scored — and
        // the trap is scoring it as SATISFIED. Failing here breaks every developer on a source build;
        // passing silently makes the pin evaporate exactly where nobody is watching for it.
        assertEquals(Config.PinVerdict.UNDETERMINED, Config.pinVerdict("v0.27.0", "unknown"));
        assertEquals(Config.PinVerdict.UNDETERMINED, Config.pinVerdict("v0.27.0", null));
        assertEquals(Config.PinVerdict.UNDETERMINED, Config.pinVerdict("v0.27.0", "  "));
        // …but an unreadable pin is still unreadable on a source build: the spelling can be checked
        // without knowing the running version, so that answer is available and is given.
        assertEquals(Config.PinVerdict.MALFORMED, Config.pinVerdict("latest", "unknown"));
    }

    @Test
    void noEngineLineIsTodaysBehaviourExactly() throws Exception {
        Config c = write("policy .candor/arch.policy\nbaseline .candor/baseline.json\n");
        assertTrue(c.enginePins().isEmpty());
        assertEquals(Config.PinVerdict.ABSENT, Config.pinVerdict(c.enginePinForThisEngine(), "0.27.0"));
    }

    @Test
    void engineIsInTheKnownVocabularySoItDoesNotWarnAsATypo() throws Exception {
        // A key outside the vocabulary is reported as unknown. If `engine` were left out, every consumer
        // adopting the pin would get "ignoring unknown config key 'engine'" — the FALSE-disclosure class
        // (the `net-partner` finding): told a key was ignored while it was being honoured.
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        java.io.PrintStream orig = System.err;
        try {
            System.setErr(new java.io.PrintStream(err));
            write("engine v0.27.0\n");
        } finally {
            System.setErr(orig);
        }
        assertFalse(err.toString().contains("unknown config key"), "`engine` is a known key: " + err);
    }
}
