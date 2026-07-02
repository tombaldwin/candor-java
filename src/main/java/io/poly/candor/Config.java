package io.poly.candor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * {@code .candor/config} — a checked-in, declarative alternative to the {@code CANDOR_*} environment
 * variables, so CI becomes "point at the repo" and the configuration travels with the code. One
 * {@code key value…} per line; {@code #} starts a comment; blank lines are ignored (the §6.2 policy
 * lexical rules).
 *
 * <p><b>Discovery is anchored to the SCAN TARGET, not the CWD:</b> the file is found by walking UP from
 * the target (`target/classes` → `target` → the repo root holding `.candor/config`), so the config that
 * travels with the scanned code is the one that applies — regardless of where the process was launched
 * (a CI step's working-directory, a `$HOME` shell). {@code CANDOR_CONFIG} overrides discovery entirely.
 *
 * <p><b>Fail-closed:</b> a config that is CONFIGURED but unusable never silently degrades to "no config"
 * (the §6.2 unreadable-policy posture — a gate source must not vanish quietly): {@code CANDOR_CONFIG}
 * naming a missing/unreadable path, or a discovered {@code .candor/config} that exists but cannot be
 * read/parsed, FAILS the run (exit 2). Only genuine ABSENCE (no file found anywhere) is an empty config.
 *
 * <p><b>Precedence</b>, highest first: a CLI flag (e.g. {@code --policy}) → the matching {@code CANDOR_*}
 * env var (a one-off override) → this file → the built-in default. So env vars still win for a one-off run.
 *
 * <p>Keys map 1:1 to the env vars: {@code policy}→CANDOR_POLICY, {@code baseline}→CANDOR_BASELINE,
 * {@code strict}→CANDOR_STRICT, {@code no-ambient}→CANDOR_NO_AMBIENT, {@code closed-world}→CANDOR_CLOSED_WORLD
 * (boolean), {@code taint}→CANDOR_TAINT (boolean), {@code deps}→CANDOR_DEPS (whitespace-separated paths here,
 * joined with the OS path separator internally). A BARE value key (e.g. a lone {@code strict} line) means
 * "enabled with the empty value" — exactly what the set-but-empty env var means (whole-unit scope for
 * {@code strict}/{@code no-ambient}); it is never silently dropped.
 */
public final class Config {
    /** The shared §config key vocabulary (cross-engine). A key OUTSIDE it warns — typo protection: a
     *  misspelt {@code policy} must not silently drop the gate. candor-java implements all seven. */
    private static final java.util.Set<String> KNOWN_KEYS = java.util.Set.of(
            "policy", "baseline", "strict", "no-ambient", "closed-world", "taint", "deps");

    private final Map<String, String> values;

    private Config(Map<String, String> values) {
        this.values = values;
    }

    static Config empty() {
        return new Config(new LinkedHashMap<>());
    }

    /** Locate + load the config for a scan of {@code scanTarget}: {@code $CANDOR_CONFIG} if set (its path
     *  MUST be usable — fail-closed), else the nearest {@code .candor/config} walking UP from the target,
     *  else the CWD's (the pre-discovery behaviour, kept for compatibility), else empty. */
    static Config forTarget(Path scanTarget) {
        String override = System.getenv("CANDOR_CONFIG");
        if (override != null) {
            Path p = Path.of(override);
            if (!Files.isRegularFile(p)) {
                // Set-but-unusable is the loud case: a typo'd CANDOR_CONFIG silently ignored is a config
                // (and therefore possibly a GATE) that vanishes quietly — the §6.2 gateless-green class.
                System.err.println("candor: CANDOR_CONFIG set but " + p + " is not a readable file — failing (exit 2)");
                System.exit(2);
            }
            return parse(p);
        }
        Path found = discover(scanTarget);
        return found != null ? parse(found) : empty();
    }

    /** The nearest {@code .candor/config} walking UP from the scan target (a classes dir, a jar, a source
     *  dir), so the checked-in config applies wherever the process is launched from; falls back to the
     *  CWD's, else null. */
    private static Path discover(Path scanTarget) {
        try {
            Path p = scanTarget.toAbsolutePath().normalize();
            if (!Files.isDirectory(p)) p = p.getParent();               // a jar/file → search from its dir
            for (; p != null; p = p.getParent()) {
                Path cfg = p.resolve(".candor/config");
                if (Files.exists(cfg)) return cfg;
            }
        } catch (RuntimeException ignored) {
            // an unresolvable target path — the scan itself will fail loudly on it; no config to find
        }
        Path cwd = Path.of(".candor/config");
        return Files.exists(cwd) ? cwd : null;
    }

    /** Parse a config file at an explicit path. The file EXISTS by the time we're here (discovery or an
     *  explicit CANDOR_CONFIG): failing to read it is a misconfiguration that MUST NOT silently drop a
     *  possible gate source — exit 2, the unreadable-policy posture. A missing path parses empty (the
     *  testable core keeps that behaviour for direct callers). */
    static Config load(Path path, boolean failClosed) {
        if (!Files.exists(path)) return empty();
        Map<String, String> m = new LinkedHashMap<>();
        try {
            for (String raw : Files.readAllLines(path)) {
                String line = raw.split("#", 2)[0].strip();     // strip an inline comment (§6.2 lexical)
                if (line.isEmpty()) continue;
                String[] kv = line.split("\\s+", 2);
                String key = kv[0].toLowerCase(Locale.ROOT);    // ROOT: 'I'→'i' even under a Turkish locale
                if (!KNOWN_KEYS.contains(key)) {
                    System.err.println("candor: ignoring unknown config key '" + key + "' in " + path);
                    continue;
                }
                String val = kv.length > 1 ? kv[1].strip() : "";
                if ("deps".equals(key) && !val.isEmpty()) {
                    val = String.join(File.pathSeparator, val.split("\\s+"));  // a path LIST → the DEPS form
                }
                m.put(key, val);
            }
        } catch (IOException e) {
            if (failClosed) {
                System.err.println("candor: config " + path + " exists but could not be read ("
                        + e.getMessage() + ") — failing (exit 2), a configured gate source must not vanish silently");
                System.exit(2);
            }
            return empty();
        }
        return new Config(m);
    }

    private static Config parse(Path path) {
        return load(path, true);
    }

    /** The testable parse core: a missing/unreadable file → empty (lenient — for direct/test callers). */
    static Config load(Path path) {
        return load(path, false);
    }

    /** A value with env-override: the env var if set (one-off override), else the config file's value —
     *  which MAY be the empty string (a bare key line: "enabled with the empty value", the set-but-empty
     *  env analog; for `strict`/`no-ambient` that means the whole unit). Null only when genuinely absent. */
    String value(String key, String envVar) {
        String env = System.getenv(envVar);
        if (env != null) return env;
        return values.get(key);
    }

    /** A boolean with env-override: the env var PRESENCE means on (env can't express off), else the config
     *  file's truthy value ({@code true}/{@code 1}/{@code yes}, or a bare key with no value). */
    boolean flag(String key, String envVar) {
        if (System.getenv(envVar) != null) return true;
        if (!values.containsKey(key)) return false;
        String v = values.get(key);
        return v.isEmpty() || v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes");
    }
}
