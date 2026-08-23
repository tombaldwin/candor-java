package io.poly.candor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import io.poly.candor.model.ReasonClass;

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
 *
 * <p><b>Relative paths are anchored to the config, not the CWD</b> (the family rule — swift/ts/agents
 * match): a relative {@code policy}/{@code baseline}/{@code deps} value resolves against the directory
 * CONTAINING the {@code .candor/} directory — the repo root the config travels with — so
 * {@code policy .candor/gate.pol} in {@code <root>/.candor/config} is {@code <root>/.candor/gate.pol}
 * wherever the process launched. (For an out-of-tree {@code CANDOR_CONFIG} override file, the anchor is
 * simply the file's own directory.) An env-var value is a one-off CLI-side override and still resolves
 * against the CWD, like a flag.
 */
public final class Config {
    /** The shared §config key vocabulary (cross-engine). A key OUTSIDE it warns — typo protection: a
     *  misspelt {@code policy} must not silently drop the gate. candor-java implements all seven + the
     *  MULTI-VALUE {@code unknown-alias} (⟨0.19⟩, reason-scoped Unknown). */
    private static final java.util.Set<String> KNOWN_KEYS = java.util.Set.of(
            "policy", "baseline", "strict", "no-ambient", "closed-world", "taint", "deps", "unknown-alias",
            "net-partner", "unknown-ratchet", "engine",
            // ⟨0.32⟩ the operator-declared classpath the compile-peek derives against. A DECLARATION, in
            // the same trust class as `net-partner`: candor will not read a project's own pom/lockfile to
            // find its dependencies, because that would let the scanned tree choose the jars its derived
            // bytecode is compiled against — an artifact could compile itself innocent.
            "peek-classpath");

    /** The implementation names an {@code engine} pin may be qualified by. The family releases on a
     *  LADDER, not in lockstep — one engine can legitimately lead a rung — so a bare version in a
     *  polyglot repo would fail whichever engine had not caught up yet. The qualified form pins each. */
    private static final java.util.Set<String> ENGINE_IMPLS =
            java.util.Set.of("java", "rust", "ts", "swift", "agents");

    /** This build's implementation name, matched against a qualified {@code engine <impl> <version>}. */
    static final String THIS_IMPL = "java";

    /** The keys whose value is a PATH (list) — the ones anchor-resolution applies to. */
    private static final java.util.Set<String> PATH_KEYS =
            java.util.Set.of("policy", "baseline", "deps", "peek-classpath");

    private final Map<String, String> values;
    /** ⟨0.19⟩ user-defined reason-class aliases (SPEC §6.2): {@code unknown-alias <name> = <class,…>}, a
     *  MULTI-VALUE key (many lines, many names) referenced EXPLICITLY as {@code Unknown[<name>]}. A spelling
     *  convenience only — it can never change what bare {@code deny E Unknown} means (that is always all
     *  classes), so a rule's denied set is legible from the policy alone. */
    private final Map<String, java.util.Set<ReasonClass>> unknownAliases;
    /** ⟨0.20⟩ config-declared `Net` PARTNER hosts (NET-DESTINATION-CLASS-DESIGN.md): {@code net-partner <host>},
     *  a MULTI-VALUE key. A partner is per-project (not universal), so it MUST be config-declared; a `Net` to a
     *  declared partner classifies {@code known-partner}, not {@code unknown-host}. Lowercased, matched
     *  subdomain-aware like {@link Literals#TELEMETRY_HOSTS}. */
    private final java.util.Set<String> netPartners;
    /** {@code engine [<impl>] <version>} — the ENGINE VERSION this repo's committed artifacts were
     *  produced with. Keyed by implementation name, or {@code *} for the unqualified form. MULTI-VALUE:
     *  a polyglot repo pins one line per engine. */
    private final Map<String, String> enginePins;

    /** ⟨0.24⟩ The file this config was read from, or null when none was found. SPEC §3.1 requires the
     *  {@code --gate-json} document to NAME a config file that supplied POLICY VOCABULARY participating in
     *  the verdict — "a verdict changed by a file the operator cannot see named in the output is the
     *  ambient-input failure this whole format exists to refuse". */
    private final Path source;

    private Config(Map<String, String> values) {
        this(values, new LinkedHashMap<>(), new java.util.LinkedHashSet<>(), new LinkedHashMap<>(), null);
    }

    private Config(Map<String, String> values, Map<String, java.util.Set<ReasonClass>> unknownAliases,
                   java.util.Set<String> netPartners, Map<String, String> enginePins, Path source) {
        this.values = values;
        this.unknownAliases = unknownAliases;
        this.netPartners = netPartners;
        this.enginePins = enginePins;
        this.source = source;
    }

    /** The file this config came from (absolute); null when none was found. */
    Path source() {
        return source;
    }

    static Config empty() {
        return new Config(new LinkedHashMap<>());
    }

    /** The resolved {@code unknown-alias} map (name → reason classes); empty when none defined. */
    Map<String, java.util.Set<ReasonClass>> unknownAliases() {
        return unknownAliases;
    }

    /** The {@code engine} pins this config declares, keyed by implementation ({@code *} = unqualified). */
    /** Every value this config supplies, already anchor-resolved. For the §3.3.1 sink guard, which must
     *  know which FILES this run reads without re-deriving how a config is parsed — see
     *  {@link Candor#runInputs}. */
    Map<String, String> valuesView() {
        return java.util.Collections.unmodifiableMap(values);
    }

    Map<String, String> enginePins() {
        return enginePins;
    }

    /** The pin that APPLIES to this build: the {@code java}-qualified one if present, else the
     *  unqualified one, else null. A qualified line naming another implementation is not ours to check —
     *  one config serves the whole family. */
    String enginePinForThisEngine() {
        // AN UNREADABLE UNQUALIFIED LINE IS STILL OURS TO READ, even when a qualified pin exists.
        // Returning the qualified pin first hid it: `engine 0.26.0 oops` beside `engine java v0.27.0`
        // exited 0 here and 2 in the other four engines — the reference engine as the sole
        // non-conformer, on the "one config, one meaning" property this rung is about. §3.4 is explicit
        // that an unqualified line "is yours to read, and MUST be MALFORMED if it is unreadable";
        // precedence decides which VERSION applies, not whether a line you were supposed to read parses.
        String wild = enginePins.get("*");
        if (wild != null && normalizeVersion(wild) == null) return wild;
        String q = enginePins.get(THIS_IMPL);
        return q != null ? q : wild;
    }

    /**
     * The four answers an {@code engine} pin can have. Kept as data rather than as a print-and-exit so
     * every branch is testable — including the two that must NOT change the exit code.
     */
    enum PinVerdict {
        /** No pin, or a pin naming another implementation. Today's behaviour, exactly. */
        ABSENT,
        /** The pin names the running build. */
        MATCH,
        /** The pin names a different version — the engine↔baseline coupling is broken. Exit 2. */
        MISMATCH,
        /** The pin is unreadable: empty, or not a version. Exit 2 — a pin that cannot be checked must
         *  not read as a pin that passed. */
        MALFORMED,
        /** The pin is well-formed and the RUNNING version is unknowable (a source build, whose
         *  build-info resource carries no release). The condition is UNANSWERABLE, so it is DISCLOSED
         *  and never scored — ⟨0.24⟩ §3.1's rule, applied to configuration. */
        UNDETERMINED
    }

    /** {@link PinVerdict} for {@code pin} against {@code running}. Pure: no printing, no exit. */
    static PinVerdict pinVerdict(String pin, String running) {
        if (pin == null) return PinVerdict.ABSENT;
        String want = normalizeVersion(pin);
        if (want == null) return PinVerdict.MALFORMED;
        if (running == null || running.isBlank() || running.equals("unknown")) return PinVerdict.UNDETERMINED;
        return want.equals(normalizeVersionLoose(running)) ? PinVerdict.MATCH : PinVerdict.MISMATCH;
    }

    /** A pin token → its comparable form, or null when it is not a version at all. A leading {@code v} is
     *  optional (the GitHub-tag spelling `v0.26.0` and the jar-filename spelling `0.26.0` are the same
     *  pin), and a two-part `0.26` is accepted as `0.26.0`. Anything else — `latest`, `main`, a git
     *  hash, an empty value — is MALFORMED rather than a version that will never match: the difference
     *  decides whether the operator is told "wrong version" or "that is not a version". */
    private static String normalizeVersion(String raw) {
        String s = raw == null ? "" : raw.strip();
        if (s.startsWith("v") || s.startsWith("V")) s = s.substring(1);
        if (!s.matches("\\d+\\.\\d+(\\.\\d+)?")) return null;
        return s.chars().filter(c -> c == '.').count() == 1 ? s + ".0" : s;
    }

    /** The running version, made comparable. Unlike a PIN this is not operator input, so a build id that
     *  does not look like a release ({@code 0.27.0-dirty}, a git hash) keeps its own spelling and simply
     *  fails to equal the pin — reported as a MISMATCH naming both, which is the truth. */
    private static String normalizeVersionLoose(String raw) {
        String n = normalizeVersion(raw);
        return n != null ? n : raw.strip();
    }

    /** The config-declared {@code net-partner} hosts (lowercased); empty when none. */
    java.util.Set<String> netPartners() {
        return netPartners;
    }

    /**
     * Parse an {@code engine} value into the pin map. Two forms:
     * <pre>
     *   engine v0.26.0          → applies to whichever engine reads it   (key `*`)
     *   engine java v0.26.0     → applies to candor-java only            (key `java`)
     * </pre>
     * <p><b>An unrecognised value is recorded, never dropped.</b> Every other malformed line in this file
     * warns and skips, which is right for a key that ADDS something — a bad {@code net-partner} costs one
     * host's classification. It is wrong here: skipping a pin the operator cannot spell turns a gate they
     * believe is on into one that is off, and the enforcement site would then see ABSENT and pass. So a
     * value that is not a version is stored as-is and classified {@link PinVerdict#MALFORMED} downstream,
     * where it exits 2 naming the line. The rule is the same one the whole file follows: a configured
     * gate source must not vanish quietly.
     *
     * <p>The one-token case is ambiguous by construction — {@code engine java} could be an impl with a
     * missing version or a version spelled `java`. It is read as the former, because a bare impl name is
     * the typo a human actually makes, and both readings end at MALFORMED anyway.
     */
    /** Record a pin, turning a CONFLICTING redefinition into one that cannot parse.
     *
     *  <p>Plain {@code put} meant last-wins, silently: {@code engine java 0.26.0} followed by
     *  {@code engine java 0.27.0} discarded the first and exited 0 MATCH. That is a pin the operator
     *  WROTE being thrown away without a word — the same failure class as the two bugs already fixed
     *  here, and the reason this key does not follow the file's ordinary last-wins convention. Two
     *  lines disagreeing about which engine to run is not a preference to resolve; it is a question the
     *  config does not answer. Keeping BOTH spellings in the value makes it fail {@code normalizeVersion}
     *  downstream, so the operator is shown the two lines they wrote. An identical repeat is harmless
     *  and stays a no-op. */
    private static void putPin(Map<String, String> pins, String key, String val) {
        String prev = pins.get(key);
        pins.put(key, prev == null || prev.equals(val) ? val : prev + " / " + val);
    }

    /** {@code String.strip()} plus U+00A0, which {@code Character.isWhitespace} excludes by definition
     *  (it is a NO-BREAK space — non-breaking is the point) and which every other engine's trim removes. */
    static boolean isSpaceLike(char c) {
        // `Character.isWhitespace` excludes the NON-BREAKING spaces BY DEFINITION — non-breaking is the
        // point — so each has to be named. Adding only U+00A0 left U+2007 (figure space) and U+202F
        // (narrow no-break space) behind: `policy gate.policy\u202F` refused at exit 2 here while the
        // other four engines trimmed it and ran, which is the false-refusal mirror of the fail-open this
        // trim was added to close. `\p{Zs}` is the whole category, so there is no next one.
        return Character.isWhitespace(c) || Character.getType(c) == Character.SPACE_SEPARATOR;
    }

    static String trimUnicode(String s) {
        int a = 0, b = s.length();
        while (a < b && isSpaceLike(s.charAt(a))) a++;
        while (b > a && isSpaceLike(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    private static void addEnginePin(Map<String, String> pins, String val) {
        // `(?U)` and an explicit Unicode trim, for the reason the KEY split has it: a NO-BREAK SPACE is
        // what pasting a config out of a rendered doc produces. Fixing only the key/value split left
        // `engine<NBSP>java<NBSP>v0.27.0` — a CORRECT qualified pin — reaching here as one token and
        // failing MALFORMED, so this engine exited 2 where the other four exited 0. A fix for a
        // fail-open that turns a working config into a refusal is the mirror defect, not a stricter
        // reading. `String.strip()` is not enough: it uses `Character.isWhitespace`, which EXCLUDES
        // U+00A0, so a trailing NBSP survived into the version.
        String v = val == null ? "" : trimUnicode(val);
        if (v.isEmpty()) { putPin(pins, "*", ""); return; }                // bare `engine` → MALFORMED
        String[] parts = v.split("[\\p{Zs}\\s]+");
        String head = parts[0].toLowerCase(Locale.ROOT);
        if (ENGINE_IMPLS.contains(head)) {
            // `engine java v0.26.0`, or `engine java` — the second is an impl with no version, MALFORMED.
            // TRAILING JUNK IS MALFORMED TOO, and taking `parts[1]` and dropping the rest was wrong in a
            // way the unqualified arm below already got right: `engine java 0.26.0 0.27.0` silently
            // pinned 0.26.0, while the unqualified `engine 0.26.0 0.27.0` correctly refused. One grammar,
            // two answers, and the qualified half was the forgiving one.
            putPin(pins, head, parts.length == 2 ? parts[1] : (parts.length == 1 ? "" : v));
            return;
        }
        // The head is not an impl, so the line is unqualified and parts[0] must BE the version. Anything
        // after it is not a second field this grammar has — `engine 0.26.0 oops` keeps the whole value so
        // the message can quote what was written. Keying on parts[0] here would have filed the pin under
        // an implementation named "0.26.0", where THIS engine never looks: a pin silently switched off.
        putPin(pins, "*", parts.length > 1 ? v : parts[0]);
    }

    /** Parse an {@code unknown-alias} value {@code <name> = <c1,c2,…>} into the map, warning-and-skipping a
     *  name that shadows a built-in ({@code *}/{@code dynamic}/a class token) or a definition naming no valid
     *  class. Shared shape with rust/ts/swift. */
    private static void addAlias(Map<String, java.util.Set<ReasonClass>> aliases, String val, Path path) {
        int eq = val.indexOf('=');
        if (eq < 0) {
            System.err.println("candor: ignoring `unknown-alias` (want `unknown-alias <name> = <class,…>`) in " + path + ": " + val);
            return;
        }
        String name = val.substring(0, eq).strip();
        String reserved = name.equals("*") || name.equals("dynamic") || ReasonClass.fromToken(name) != null ? name : null;
        if (name.isEmpty() || reserved != null) {
            System.err.println("candor: ignoring `unknown-alias` with " + (name.isEmpty() ? "no name" : "reserved name `" + reserved + "`")
                    + " (a config alias may not shadow `*`/`dynamic`/a class token) in " + path);
            return;
        }
        java.util.Set<ReasonClass> classes = new java.util.LinkedHashSet<>();
        for (String cn : val.substring(eq + 1).split(",")) {
            cn = cn.strip();
            if (cn.isEmpty()) continue;
            if (cn.equals("dynamic")) { classes.addAll(ReasonClass.dynamicSet()); continue; }
            ReasonClass rc = ReasonClass.fromToken(cn);
            if (rc == null) System.err.println("candor: `unknown-alias " + name + "` names unknown reason-class `" + cn + "` in " + path + " — skipped");
            else classes.add(rc);
        }
        if (classes.isEmpty()) System.err.println("candor: ignoring `unknown-alias " + name + "` — no valid reason-class in " + path);
        else aliases.put(name, classes);
    }

    /** The resolution base for a relative path VALUE in the config at {@code cfg}: the directory holding
     *  the {@code .candor/} directory (step the trailing {@code .candor} segment out), else the file's own
     *  directory (an out-of-tree CANDOR_CONFIG override). Absolute, so the resolved values are launch-dir
     *  independent — the whole point of a checked-in config. */
    static Path anchorFor(Path cfg) {
        Path dir = cfg.toAbsolutePath().normalize().getParent();
        if (dir != null && dir.getFileName() != null && dir.getFileName().toString().equals(".candor")) {
            Path up = dir.getParent();
            if (up != null) return up;
        }
        return dir;
    }

    /** Resolve one relative path against the anchor; an absolute path is untouched. */
    private static String resolveAgainst(Path anchor, String val) {
        if (val.isEmpty() || anchor == null) return val;
        Path p = Path.of(val);
        return p.isAbsolute() ? val : anchor.resolve(p).normalize().toString();
    }

    /** Locate + load the config for a scan of {@code scanTarget}: {@code $CANDOR_CONFIG} if set (its path
     *  MUST be usable — fail-closed), else the nearest {@code .candor/config} walking UP from the target,
     *  else empty. */
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

    /**
     * ⟨0.24⟩ <b>POLICY VOCABULARY ANCHORS AT THE POLICY FILE, ON BOTH ROUTES — SPEC §3.1.</b>
     *
     * <p>§3.1's MUST NOT names three channels through which an effect must never enter a gate that its
     * report does not carry. A review found a fourth: {@code .candor/config}'s {@code unknown-alias}. All
     * four GATE verbs anchored discovery at the POLICY file's directory while all four SCAN routes
     * anchored at the TARGET — so with the policy filed outside the scan target, {@code scan --policy P}
     * and {@code gate --report R --policy P} expand the same rule differently, and <b>§3.1's byte-equality
     * MUST is breakable by a file that is neither the report nor the policy.</b>
     *
     * <p>MEASURED on this engine at 2cdc443, with {@code unknown-alias corp = native} beside the policy,
     * the scan target carrying no config, and the target's one {@code Unknown} being {@code reflect}-caused:
     * <pre>
     *   scan --policy polhome/my.policy              →  exit 1   (alias unresolved → rule WIDENED to bare Unknown)
     *   gate --report r --policy polhome/my.policy   →  exit 0   (alias resolved → deny Unknown[native], no match)
     * </pre>
     * Same report, same policy, two verdicts, and the fail-open one is the gate.
     *
     * <p><b>RULING.</b> {@code unknown-alias} — and any future key that supplies POLICY VOCABULARY rather
     * than scan configuration — resolves relative to the {@code --policy} file's directory on BOTH routes
     * when {@code --policy} is given explicitly. Vocabulary travels with the policy that uses it;
     * TARGET-scoped keys ({@code deps}, {@code net-partner}, scan settings) keep anchoring at the target,
     * because they describe the thing being scanned. Byte-equality then holds BY CONSTRUCTION rather than
     * by the two routes happening to be pointed at the same directory.
     */
    static Config policyVocabulary(Path policyFile) {
        return forTarget(policyFile);
    }

    /** The nearest {@code .candor/config} walking UP from the scan target (a classes dir, a jar, a source
     *  dir), so the checked-in config applies wherever the process is launched from; else null. NO CWD
     *  fallback (the spec-§3.4 contradiction the family deleted): it fired only when the CWD was OUTSIDE
     *  the target's ancestry — i.e. it applied an UNRELATED repo's config (and its policy/gates) to the
     *  scan. Discovery is target-anchored only; {@code CANDOR_CONFIG} is the only override. */
    static Path discover(Path scanTarget) {
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
        return null;
    }

    /** Parse a config file at an explicit path. The file EXISTS by the time we're here (discovery or an
     *  explicit CANDOR_CONFIG): failing to read it is a misconfiguration that MUST NOT silently drop a
     *  possible gate source — exit 2, the unreadable-policy posture. A missing path parses empty (the
     *  testable core keeps that behaviour for direct callers). */
    static Config load(Path path, boolean failClosed) {
        if (!Files.exists(path)) return empty();
        Map<String, String> m = new LinkedHashMap<>();
        Map<String, java.util.Set<ReasonClass>> aliases = new LinkedHashMap<>();
        java.util.Set<String> partners = new java.util.LinkedHashSet<>();
        Map<String, String> pins = new LinkedHashMap<>();
        Path anchor = anchorFor(path);
        try {
            for (String raw : Files.readAllLines(path)) {
                // `trimUnicode`, not `strip()`: a LEADING U+00A0/U+2007/U+202F survived `strip()`, so the
                // key/value split produced an EMPTY first token and the line vanished as "unknown config
                // key ''" — a `policy` line silently dropped (gateless green) and a MISMATCHED `engine`
                // pin silently passed, where the other four engines refused.
                String line = trimUnicode(raw.split("#", 2)[0]);   // strip an inline comment (§6.2 lexical)
                if (line.isEmpty()) continue;
                // (?U) — UNICODE whitespace, matching the other four engines. Java's bare `\s` is
                // ASCII-only, so a NO-BREAK SPACE (U+00A0, the ordinary artifact of pasting a config
                // out of a rendered doc) left `engine\u00A0` as ONE token: not the key `engine`, so
                // the line was reported as an "unknown config key 'engine '" — a FALSE disclosure,
                // since the pin it names was silently NOT ENFORCED and a MISMATCHED pin passed at
                // exit 0. rust/ts/agents all split on Unicode whitespace and exit 2 here.
                String[] kv = line.split("[\\p{Zs}\\s]+", 2);
                String key = kv[0].toLowerCase(Locale.ROOT);    // ROOT: 'I'→'i' even under a Turkish locale
                if (!KNOWN_KEYS.contains(key)) {
                    System.err.println("candor: ignoring unknown config key '" + key + "' in " + path);
                    continue;
                }
                String val = kv.length > 1 ? trimUnicode(kv[1]) : "";
                if ("unknown-alias".equals(key)) {   // ⟨0.19⟩ MULTI-VALUE: many names, kept out of `values`
                    addAlias(aliases, val, path);
                    continue;
                }
                if ("net-partner".equals(key)) {     // ⟨0.20⟩ MULTI-VALUE: declared Net partner hosts
                    // ⟨0.29⟩ …and a MALFORMED value is DISCLOSED, not kept as junk. The grammar is
                    // `net-partner <host>`; the `=` spelling an operator reaches for by habit
                    // (`net-partner = partner.example`) parsed as the HOST "= partner.example", entered
                    // the set, and matched nothing for the rest of the run. The direction is SAFE — the
                    // gate stays armed — which is exactly why it sat unnoticed: the operator believes a
                    // partner is declared, the verdict disagrees, and no line connects the two. This
                    // file's own contract, stated a hundred lines up, is that *every other malformed line
                    // here warns and skips*; this key was the exception.
                    if (!val.isEmpty()) {
                        if (val.chars().anyMatch(Character::isWhitespace) || val.startsWith("=")) {
                            System.err.println("candor: net-partner takes a bare host — `net-partner "
                                    + "<host>`, one per line; '" + val + "' is not one and was IGNORED "
                                    + "(an '=' or extra words is the usual cause)");
                        } else {
                            partners.add(Literals.hostPart(val).toLowerCase(Locale.ROOT));
                        }
                    }
                    continue;
                }
                if ("engine".equals(key)) {          // MULTI-VALUE: `engine [<impl>] <version>`
                    addEnginePin(pins, val);
                    continue;
                }
                if ("deps".equals(key) && !val.isEmpty()) {
                    // a path LIST → the DEPS form, each element anchor-resolved
                    // ASCII whitespace ONLY, deliberately, and NOT `(?U)`: these are PATHS, and a
                    // path may legitimately contain a NO-BREAK SPACE. Splitting there loses half of it —
                    // candor-ts drops such a dep and stays green, candor-swift refuses at exit 2, and both
                    // are wrong in different directions. The separator is a space; the value is a filename.
                    val = java.util.Arrays.stream(val.split("[ \\t]+"))
                            .map(v -> resolveAgainst(anchor, v))
                            .collect(java.util.stream.Collectors.joining(File.pathSeparator));
                } else if (PATH_KEYS.contains(key)) {
                    val = resolveAgainst(anchor, val);
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
        return new Config(m, aliases, partners, pins, path.toAbsolutePath().normalize());
    }

    private static Config parse(Path path) {
        return load(path, true);
    }

    /** The testable parse core: a missing/unreadable file → empty (lenient — for direct/test callers). */
    static Config load(Path path) {
        return load(path, false);
    }

    /** Did this key's value come from the CHECKED-IN FILE rather than the environment?
     *
     *  <p>The two are not interchangeable for a MISSING file. `CANDOR_BASELINE` is set unconditionally by
     *  the adopt workflow, so a path that does not exist there means "the ratchet is not adopted yet" —
     *  a note. A `baseline` line in `.candor/config` is a CHECKED-IN DECLARATION that this repo has one,
     *  so a missing file there means it was deleted or never committed, and the gate quietly not gating
     *  is the §6.2 gateless-green class. Same absence, opposite meanings; only the SOURCE separates them.
     */
    boolean fromFile(String key, String envVar) {
        return System.getenv(envVar) == null && values.containsKey(key);
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
