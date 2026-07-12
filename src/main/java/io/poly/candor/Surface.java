package io.poly.candor;

import java.io.PrintStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

/**
 * Surface the single most SURPRISING transitive reach — the cold-repo hook.
 *
 * <p>After the effect summary + the κ-coverage ledger, candor emits ONE more stderr line: the single
 * most surprising transitive reach in the scanned code (a benign-named function inheriting a boundary
 * effect from a few hops away) plus a ready-to-run {@code candor path} command. When nothing clears the
 * bar it emits an honest "nothing hidden" fallback instead — never a manufactured surprise.
 *
 * <p>This is the EXACT port of the Rust reference {@code candor-scan/src/surface.rs} — same lexicons,
 * same scoring, same deterministic tie-break — so every engine surfaces the SAME reach on a shared
 * fixture. Fully deterministic: pure call-graph + name analysis, NO LLM. The find is never <em>wrong</em>:
 * {@code candor path <F> <E>} re-derives the chain and the gate is ground truth.
 *
 * <p>The one Java-specific adaptation is the qualified-name SEPARATOR: candor-java node ids are dotted
 * ({@code com.example.Settings.load}), so leaf/module split on {@code '.'} and test code is skipped by a
 * {@code .tests.}/{@code .test.} substring (the Rust reference skips {@code ::tests::}/{@code ::test::}).
 */
final class Surface {

    private Surface() {}

    /** Name tokens that read as local / pure / config — a function whose leaf is named like this reaching a
     *  scary effect is the core surprise signal. COPIED VERBATIM from the Rust reference's BENIGN list. */
    static final Set<String> BENIGN = Set.of(
            "settings", "config", "conf", "options", "opts", "util", "utils", "helper", "helpers", "model",
            "models", "dto", "entity", "format", "fmt", "parse", "get", "load", "new", "default", "validate",
            "valid", "render", "view", "build", "builder", "item", "entry", "record", "state", "context",
            "ctx", "info", "meta", "data", "value", "node", "field", "name", "key", "id", "path", "kind",
            "type", "status", "check", "init", "setup");

    /** Name tokens that are effect-suggestive — a function in/near an effect-flavored context reaching that
     *  effect is EXPECTED, not surprising, so we EXCLUDE it. COPIED VERBATIM from the Rust reference. */
    static final Set<String> EFFECTY = Set.of(
            "fetch", "http", "https", "client", "api", "sync", "request", "req", "download", "upload", "query",
            "sql", "store", "save", "persist", "connect", "conn", "socket", "send", "recv", "read", "write",
            "open", "file", "fs", "io", "net", "tcp", "udp", "dns", "url", "host", "port", "cmd", "command",
            "shell", "process", "proc", "exec", "spawn", "env", "clock", "time", "now", "rand", "random",
            "log", "logger", "trace", "db");

    /** Split a qualified name (or a leaf) into lowercase tokens on {@code '_'}, {@code '.'} and camelCase
     *  boundaries. The Rust reference splits on {@code '_'} and {@code ':'}; here the qualified-name
     *  separator is {@code '.'} (dotted JVM node ids). */
    static List<String> tokenize(String name) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean prevLower = false;
        for (int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            if (ch == '_' || ch == '.' || ch == ':') {
                if (cur.length() > 0) {
                    out.add(cur.toString());
                    cur.setLength(0);
                }
                prevLower = false;
                continue;
            }
            // camelCase boundary: a lower/digit followed by an upper starts a new token.
            if (Character.isUpperCase(ch) && prevLower && cur.length() > 0) {
                out.add(cur.toString());
                cur.setLength(0);
            }
            cur.append(Character.toLowerCase(ch));
            prevLower = Character.isLowerCase(ch) || Character.isDigit(ch);
        }
        if (cur.length() > 0) {
            out.add(cur.toString());
        }
        return out;
    }

    /** The leaf (final dotted segment) of a qualified name. */
    static String leaf(String qual) {
        int i = qual.lastIndexOf('.');
        return i < 0 ? qual : qual.substring(i + 1);
    }

    /** The module portion of a qualified name (everything before the leaf); "" when there is no dot. */
    static String moduleOf(String qual) {
        int i = qual.lastIndexOf('.');
        return i < 0 ? "" : qual.substring(0, i);
    }

    /** The first token of {@code name} that appears in {@code lexicon}, or {@code null}. */
    static String hasToken(String name, Set<String> lexicon) {
        for (String t : tokenize(name)) {
            if (lexicon.contains(t)) return t;
        }
        return null;
    }

    /** Salience of an effect — boundary/security-relevant effects a reviewer cares about score higher. */
    static long salience(String effect) {
        switch (effect) {
            case "Net": case "Exec": case "Db": case "Ipc": return 5;
            case "Fs": case "Env": return 3;
            case "Clock": case "Log": case "Rand": return 1;
            default: return 0;
        }
    }

    static long hopsFactor(int hops) {
        if (hops == 1) return 2;
        if (hops >= 2 && hops <= 4) return 3;
        if (hops >= 5 && hops <= 6) return 2;
        return 1; // >=7 (hops is always >=1 for an inherited reach)
    }

    /** Skip test code: the Rust reference skips {@code ::tests::}/{@code ::test::}; the dotted analogue. */
    static boolean isTest(String qual) {
        return qual.contains(".tests.") || qual.contains(".test.");
    }

    /** A scored candidate reach. */
    static final class Find {
        final String func;
        final String effect;
        final int hops;
        final String source;
        final String benignToken; // "" when the leaf has no benign token
        final long score;

        Find(String func, String effect, int hops, String source, String benignToken, long score) {
            this.func = func;
            this.effect = effect;
            this.hops = hops;
            this.source = source;
            this.benignToken = benignToken;
            this.score = score;
        }
    }

    /** BFS from {@code func} over {@code calls} (follow callees, shortest hops) to the nearest function
     *  {@code S} with {@code effect} ∈ direct[S]. Returns {@code [hops>=1, S]}, or {@code null} if none.
     *  Only traverses through callees whose INFERRED set carries the effect, so the frontier stays
     *  on-effect (matches {@code candor path}'s walk). */
    static Object[] nearestSource(String func, String effect,
            Map<String, EffectSet> direct, Map<String, EffectSet> inferred, Map<String, Set<String>> calls) {
        Effect e = Effect.fromSpecName(effect);
        Set<String> seen = new TreeSet<>();
        Deque<Object[]> q = new ArrayDeque<>();
        seen.add(func);
        q.addLast(new Object[]{func, 0});
        while (!q.isEmpty()) {
            Object[] head = q.pollFirst();
            String cur = (String) head[0];
            int d = (int) head[1];
            // A direct source found at distance d>=1 is the nearest (BFS). The start `func` itself is an
            // INHERITED reach (E ∉ direct[func]) so it never matches at d==0.
            EffectSet cd = direct.get(cur);
            if (d >= 1 && cd != null && cd.contains(e)) {
                return new Object[]{d, cur};
            }
            Set<String> cs = calls.get(cur);
            if (cs != null) {
                // Deterministic frontier order: sorted callees (BFS distance is unaffected, but a stable
                // order keeps the traversal reproducible).
                for (String c : new TreeSet<>(cs)) {
                    EffectSet ci = inferred.get(c);
                    if (!seen.contains(c) && ci != null && ci.contains(e)) {
                        seen.add(c);
                        q.addLast(new Object[]{c, d + 1});
                    }
                }
            }
        }
        return null;
    }

    /** The three-state result of {@link #bestFind}: {@code state == NONE} → emit nothing (zero effectful
     *  functions); {@code state == FALLBACK} → the honest fallback; {@code state == WINNER} → {@link #find}. */
    static final class Result {
        enum State { NONE, FALLBACK, WINNER }
        final State state;
        final Find find;
        private Result(State state, Find find) { this.state = state; this.find = find; }
        static final Result NONE = new Result(State.NONE, null);
        static final Result FALLBACK = new Result(State.FALLBACK, null);
        static Result winner(Find f) { return new Result(State.WINNER, f); }
    }

    /** Compute the single most surprising reach. {@code NONE} when there are ZERO effectful functions;
     *  {@code FALLBACK} when there were effectful functions but none cleared the bar; {@code WINNER}
     *  otherwise. Mirrors the Rust reference's {@code Option<Option<Find>>}. */
    static Result bestFind(Map<String, EffectSet> inferred, Map<String, EffectSet> direct,
            Map<String, Set<String>> calls) {
        // Any function carrying a real (non-Unknown) effect makes the code "effectful" — governs whether we
        // emit the fallback vs nothing.
        boolean anyEffectful = false;

        // Deterministic iteration: sort quals ascending so the tie-break (qual ascending) is stable and
        // HashMap order never leaks into the result.
        List<String> quals = new ArrayList<>(inferred.keySet());
        quals.sort(null);

        Find best = null;

        for (String f : quals) {
            EffectSet inf = inferred.get(f);
            for (Effect ef : inf.effects()) {
                if (ef != Effect.UNKNOWN) { anyEffectful = true; break; }
            }
            if (isTest(f)) {
                continue;
            }
            String fLeaf = leaf(f);
            String fMod = moduleOf(f);
            // EXCLUDE the whole function if its leaf OR module reads effecty — its reach is obvious.
            if (hasToken(fLeaf, EFFECTY) != null || hasToken(fMod, EFFECTY) != null) {
                continue;
            }
            EffectSet dir = direct.getOrDefault(f, EffectSet.empty());
            // Candidate effects: inherited (in inferred, not direct), not Unknown. Sorted spec-name order
            // matches the Rust reference's ascending effect iteration.
            List<String> effects = new ArrayList<>();
            for (String name : inf.toNames()) {
                if (!name.equals("Unknown") && !dir.contains(Effect.fromSpecName(name))) {
                    effects.add(name);
                }
            }
            // toNames() is already sorted ascending; keep an explicit sort for parity with the reference.
            effects.sort(null);
            for (String e : effects) {
                long sal = salience(e);
                if (sal == 0) {
                    continue;
                }
                Object[] ns = nearestSource(f, e, direct, inferred, calls);
                if (ns == null) {
                    continue; // no LOCAL direct source — nothing to show
                }
                int hops = (int) ns[0];
                String s = (String) ns[1];
                String benign = hasToken(fLeaf, BENIGN);
                long benignity = benign != null ? 3 : 1;
                long crossing = !moduleOf(s).equals(fMod) ? 2 : 1;
                long score = sal * benignity * hopsFactor(hops) * crossing;
                if (score == 0) {
                    continue;
                }
                Find cand = new Find(f, e, hops, s, benign != null ? benign : "", score);
                // Tie-break: higher score, then fewer hops, then qual ascending. Quals are iterated
                // ascending and effects ascending, so a strict > keeps the first (smallest qual) winner.
                boolean better;
                if (best == null) {
                    better = true;
                } else {
                    better = cand.score > best.score
                            || (cand.score == best.score && cand.hops < best.hops);
                    // equal score & hops: earlier qual already seen (ascending iteration) → keep it.
                }
                if (better) {
                    best = cand;
                }
            }
        }

        if (!anyEffectful) {
            return Result.NONE;
        }
        return best == null ? Result.FALLBACK : Result.winner(best);
    }

    /** Emit the surface note to {@code err}, after the coverage-ledger line. {@code loc} maps qual →
     *  "file:line" for the source callout. Marker is {@code "candor:"} (the brand/dispatcher voice, not
     *  {@code candor-java:}), and the suggested command is {@code candor path …} — same on every engine. */
    static void emit(Map<String, EffectSet> inferred, Map<String, EffectSet> direct,
            Map<String, Set<String>> calls, Map<String, String> loc, PrintStream err) {
        Result r = bestFind(inferred, direct, calls);
        switch (r.state) {
            case NONE:
                return; // zero effectful functions — emit nothing
            case FALLBACK:
                err.println("candor: nothing hidden — every effect sits where its name says it should.");
                return;
            case WINNER:
                Find f = r.find;
                String whereS = loc.getOrDefault(f.source, "?");
                String hopWord = f.hops == 1 ? "hop" : "hops";
                String benignNote = f.benignToken.isEmpty()
                        ? ""
                        : String.format("          a \"%s\"-named function reaching %s.%n", f.benignToken, f.effect);
                err.printf(
                        "candor: most surprising reach — `%s` performs %s, %d %s away via `%s` (%s).%n%s          →  candor path %s %s%n",
                        f.func, f.effect, f.hops, hopWord, f.source, whereS, benignNote, f.func, f.effect);
                return;
        }
    }
}
