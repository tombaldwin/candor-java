package io.poly.candor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code .candor/config} — a checked-in, declarative alternative to the {@code CANDOR_*} environment
 * variables, so CI becomes "point at the repo" and the configuration travels with the code. One
 * {@code key value…} per line; {@code #} starts a comment; blank lines are ignored (the §6.2 policy
 * lexical rules). A missing file is fine — an empty config.
 *
 * <p><b>Precedence</b>, highest first: a CLI flag (e.g. {@code --policy}) → the matching {@code CANDOR_*}
 * env var (a one-off override) → this file → the built-in default. So env vars still win for a one-off run.
 *
 * <p>Keys map 1:1 to the env vars: {@code policy}→CANDOR_POLICY, {@code baseline}→CANDOR_BASELINE,
 * {@code strict}→CANDOR_STRICT, {@code no-ambient}→CANDOR_NO_AMBIENT, {@code closed-world}→CANDOR_CLOSED_WORLD
 * (boolean), {@code taint}→CANDOR_TAINT (boolean), {@code deps}→CANDOR_DEPS (whitespace-separated paths here,
 * joined with the OS path separator internally). The file itself is located at {@code .candor/config}, or the
 * path in {@code CANDOR_CONFIG}.
 */
public final class Config {
    private final Map<String, String> values;

    private Config(Map<String, String> values) {
        this.values = values;
    }

    static Config empty() {
        return new Config(new LinkedHashMap<>());
    }

    /** Load {@code .candor/config} (or {@code $CANDOR_CONFIG}); a missing/unreadable file → an empty config. */
    static Config load() {
        String override = System.getenv("CANDOR_CONFIG");
        return load(Path.of(override != null ? override : ".candor/config"));
    }

    /** Parse a config file at an explicit path (the testable core of {@link #load()}). */
    static Config load(Path path) {
        Map<String, String> m = new LinkedHashMap<>();
        if (Files.isRegularFile(path)) {
            try {
                for (String raw : Files.readAllLines(path)) {
                    String line = raw.split("#", 2)[0].strip();     // strip an inline comment (§6.2 lexical)
                    if (line.isEmpty()) continue;
                    String[] kv = line.split("\\s+", 2);
                    String key = kv[0].toLowerCase();
                    String val = kv.length > 1 ? kv[1].strip() : "";
                    if ("deps".equals(key) && !val.isEmpty()) {
                        val = String.join(File.pathSeparator, val.split("\\s+"));  // a path LIST → the DEPS form
                    }
                    m.put(key, val);
                }
            } catch (IOException e) {
                System.err.println("candor: could not read " + path + ": " + e.getMessage() + " — ignoring config");
            }
        }
        return new Config(m);
    }

    /** A value with env-override: the env var if set (one-off override), else the config file, else null. */
    String value(String key, String envVar) {
        String env = System.getenv(envVar);
        if (env != null) return env;
        String v = values.get(key);
        return (v != null && !v.isEmpty()) ? v : null;
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
