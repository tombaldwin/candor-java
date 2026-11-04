package io.poly.candor;

import io.poly.candor.model.DiagnosticCode;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.PolicyRule;
import io.poly.candor.model.ReasonClass;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SPEC §6.2 ⟨0.41⟩ — {@code accept <fn> [<Effect>…] for <rule tokens…> because <reason…>}: a KNOWN violation,
 * written down where a reviewer reads it.
 *
 * <p><b>THE CARDINAL DIRECTION HERE IS ACCEPTING A VIOLATION THAT IS NEW.</b> Every decision below is made
 * so that doubt leaves the row RED: a line this class cannot read exactly is ignored (and listed in
 * {@code ignored}), a key it cannot trust (a positional one) is refused, a twin it cannot tell apart accepts
 * neither, an {@code Unknown} it cannot classify is not covered. A bug in this file may therefore cost a
 * false red; it must not cost a false green.
 *
 * <p>Three pieces, in the order a run meets them:
 * <ol>
 *   <li>{@link #resolve}: after the policy is read, turn each {@code accept} line into an {@link Entry} or
 *       an {@code ignored} row, or a policy error for an unrecognised effect / class token;</li>
 *   <li>{@link #settle}: called by {@link Policy#gate} with the rows ONE producing rule line made, before any
 *       de-duplication, deciding which are accepted — the rows that survive are emitted by the caller
 *       exactly as before, so a run with no entry is byte-identical to a run without this class;</li>
 *   <li>{@link #finish}: statuses, the stale {@code AS-EFF-012} rows and the {@code accepted} document key.</li>
 * </ol>
 */
final class Accept {
    private Accept() {}

    /** One parsed, valid {@code accept} line. {@code classes} is null when the entry does not list
     *  {@code Unknown}; otherwise the explicit reason classes it covers. */
    record Entry(int line, String fn, TreeSet<String> effects, Set<String> classes, String ruleKey,
                 String because, String raw) {}

    /** One row a rule line produced, held back until acceptance is decided. {@code emit} writes the row and
     *  is run for exactly the rows that were NOT accepted. */
    static final class Row {
        final String ruleKey, code, name, hash;
        final List<String> effects;
        final Set<String> classes;
        final Runnable emit;
        Row(String ruleKey, String code, String name, String hash, List<String> effects,
            Set<String> classes, Runnable emit) {
            this.ruleKey = ruleKey; this.code = code; this.name = name; this.hash = hash;
            this.effects = effects; this.classes = classes; this.emit = emit;
        }
    }

    // ------------------------------------------------------------------------------------------------
    // per-run state (statics, like every other per-parse channel in Policy)
    // ------------------------------------------------------------------------------------------------
    static final List<Entry> entries = new ArrayList<>();
    /** Rule keys (raw tokens, single-spaced) the caller could not evaluate on this route — set by
     *  {@code gate --report} just before it gates; consumed (and cleared) by {@link #begin}. */
    private static Set<String> pendingUnevaluated = new HashSet<>();
    private static Set<String> unevaluated = new HashSet<>();
    private static Set<String> twinNames = new HashSet<>();
    /** per entry line: the rows it accepted directly / as the enclosing entry of a nested unit */
    private static final Map<Integer, List<Row>> directBy = new HashMap<>();
    private static final Map<Integer, List<Object[]>> nestedBy = new HashMap<>();   // {Row nested, Row enclosing}
    private static final List<Row> remaining = new ArrayList<>();
    private static int acceptedRows;
    /** ⟨0.41⟩ Set only by the {@code accepts} verb: compute {@link #twinNames} even when the policy holds no entry, so
     *  {@code --adopt} over a policy with no {@code accept} line still refuses a (hash, fn) twin. Never read by a gate. */
    static boolean forceTwins = false;
    /** ⟨0.41⟩ The policy lines of the entries {@link #finish} made AS-EFF-012 rows in the last gate — for {@code accepts},
     *  which deletes exactly those lines and so must not re-derive staleness from the row's message text. */
    private static Set<Integer> staleLinesLast = new TreeSet<>();
    static Set<Integer> staleLines() { return new TreeSet<>(staleLinesLast); }
    /** The {@code accepted} verdict list, built by {@link #finish}; null when no entry exists. */
    static List<Map<String, Object>> accepted = null;

    static String key(String rawRule) {
        return String.join(" ", rawRule.trim().split("\\s+"));
    }

    static void setUnevaluated(Collection<String[]> rows) {
        Set<String> s = new HashSet<>();
        for (String[] r : rows) if (r != null && r.length > 0 && r[0] != null) s.add(key(r[0]));
        pendingUnevaluated = s;
    }

    static boolean any() { return !entries.isEmpty(); }

    // ------------------------------------------------------------------------------------------------
    // 1. parse
    // ------------------------------------------------------------------------------------------------
    private static final Set<String> CLASS_ALIASES = Set.of("*", "dynamic");

    /** The raw lexed tokens of one {@code accept} line, held until every rule line has been read (an entry
     *  may name a rule that comes AFTER it). */
    record Pending(int lineNo, String raw, String[] tokens) {}

    /** JAVA'S POSITIONAL SPELLINGS (§6.2: "the engine knows its own and refuses them"). A name the compiler
     *  numbers by position: a javac lambda {@code lambda$m$N}, an anonymous or local class {@code C$1} /
     *  {@code C$1Local}, a synthetic accessor {@code access$000}, Kotlin's {@code $lambda$} and
     *  {@code $1} classes, Scala's {@code $anonfun$}, Groovy's {@code _closureN}. Inserting one unrelated
     *  lambda or anonymous class renumbers every later one, so an entry on such a key would accept DIFFERENT
     *  code after the edit. Over-matching a legitimate name that merely contains one of these shapes errs
     *  RED (the line is ignored and the violation stays). */
    private static final Pattern POSITIONAL = Pattern.compile(
            "(^|[.$])lambda\\$|\\$\\d+|(^|[.$])access\\$\\d+|\\$anonfun\\$|\\$deserializeLambda\\$|_closure\\d+");

    static boolean positional(String fn) {
        return POSITIONAL.matcher(fn).find();
    }

    /** Resolve the pending lines against the rules THIS parse produced. Called once, at the end of
     *  {@link Policy#parsePolicy}. */
    static void resolve(List<Pending> pending, List<PolicyRule.Deny> deny, List<PolicyRule.Forbid> forbid,
                        List<PolicyRule.Allow> allow, List<PolicyRule.Only> only) {
        entries.clear();
        if (pending.isEmpty()) return;
        Set<String> denyKeys = new HashSet<>(), forbidKeys = new HashSet<>(), otherKeys = new HashSet<>();
        for (var r : deny) denyKeys.add(key(r.src()));
        for (var r : forbid) forbidKeys.add(key(r.src()));
        for (var r : allow) otherKeys.add(key(r.src()));
        for (var r : only) otherKeys.add(key(r.src()));
        for (Pending p : pending) {
            Policy.setCursor(p.lineNo(), p.raw());
            String line = p.raw().split("#", 2)[0].trim();
            String[] t = p.tokens();
            // t[0] == "accept"
            if (t.length < 2) { Policy.warnPolicy(line, "rule-form", "", List.of(), "accept names no function"); continue; }
            String fn = t[1];
            int forAt = -1;
            for (int i = 2; i < t.length; i++) if (t[i].equals("for")) { forAt = i; break; }
            if (forAt < 0) { Policy.warnPolicy(line, "rule-form", "", List.of(), "accept lacks the literal `for`"); continue; }
            int becAt = -1;
            for (int i = forAt + 1; i < t.length; i++) if (t[i].equals("because")) { becAt = i; break; }
            if (becAt < 0 || becAt == t.length - 1) {
                Policy.warnPolicy(line, "rule-form", "", List.of(),
                        "accept carries no reason — write `because <why>` (a `#` begins a comment, so `because #123` is empty)");
                continue;
            }
            String ruleKey = String.join(" ", Arrays.copyOfRange(t, forAt + 1, becAt));
            String because = String.join(" ", Arrays.copyOfRange(t, becAt + 1, t.length));
            // ---- the effect list --------------------------------------------------------------------
            TreeSet<String> names = new TreeSet<>();
            Set<String> classes = null;
            boolean malformed = false;
            String why = null;
            for (int i = 2; i < forAt; i++) {
                String e = t[i];
                if (e.equals("Unknown") || (e.startsWith("Unknown[") && e.endsWith("]"))) {
                    if (e.equals("Unknown")) { malformed = true; why = "bare `Unknown` — write an explicit class list, `Unknown[dispatch]`"; continue; }
                    String inner = e.substring("Unknown[".length(), e.length() - 1);
                    boolean any = false;
                    for (String cn : inner.split(",", -1)) {
                        cn = cn.trim();
                        if (cn.isEmpty()) { malformed = true; why = "empty class in `" + e + "`"; continue; }
                        if (CLASS_ALIASES.contains(cn) || Policy.isUnknownAlias(cn)) {
                            malformed = true;
                            why = "`" + cn + "` is an alias, not a reason class — list the classes by name";
                            continue;
                        }
                        ReasonClass rc = ReasonClass.fromToken(cn);
                        if (rc == null) {
                            Policy.policyError(line, "reason-class/alias", cn,
                                    List.of("reflect", "dispatch", "indirect", "native", "unresolved", "setup"),
                                    "reflect, dispatch, indirect, native, unresolved, setup");
                            continue;
                        }
                        if (classes == null) classes = new TreeSet<>();
                        classes.add(rc.token());
                        any = true;
                    }
                    if (any) names.add("Unknown");
                } else if (e.indexOf('[') >= 0) {
                    malformed = true;
                    why = "`" + e + "`: only `Unknown` takes a bracketed filter on an accept line";
                } else if (Rules.KNOWN_EFFECTS.contains(e)) {
                    names.add(e);
                } else {
                    Policy.policyError(line, "effect-name", e, Policy.knownEffectNamesForAccept(),
                            String.join(", ", Policy.knownEffectNamesForAccept()));
                }
            }
            if (Policy.policyUnhonourable()) continue;     // the whole policy is refused; nothing else to say
            if (malformed) { Policy.warnPolicy(line, "rule-form", "", List.of(), "accept: " + why); continue; }
            // ---- the rule it names ------------------------------------------------------------------
            boolean isDeny = denyKeys.contains(ruleKey), isForbid = forbidKeys.contains(ruleKey);
            if (otherKeys.contains(ruleKey) && !isDeny && !isForbid) {
                Policy.warnPolicy(line, "rule-form", "", List.of(),
                        "accept cannot name an `allow` or `only` rule — its row does not say which value or scope was reached, "
                                + "so an entry would silently accept a NEW one");
                continue;
            }
            if (!isDeny && !isForbid) {
                Policy.warnPolicy(line, "rule-form", "", List.of(),
                        "accept names no deny/pure/forbid line of this file — the tokens between `for` and `because` must equal a rule line's tokens");
                continue;
            }
            if (isDeny && names.isEmpty()) {
                Policy.warnPolicy(line, "rule-form", "", List.of(), "accept for a deny/pure rule must list at least one effect");
                continue;
            }
            if (isForbid && !names.isEmpty()) {
                Policy.warnPolicy(line, "rule-form", "", List.of(), "accept for a forbid rule takes no effects");
                continue;
            }
            if (positional(fn)) {
                Policy.warnPolicy(line, "rule-form", "", List.of(),
                        "accept names a positional key (`" + fn + "`, numbered by the compiler): an unrelated edit renumbers it and the "
                                + "entry would accept DIFFERENT code. Accept the enclosing method instead — its entry also covers the "
                                + "lambda it calls");
                continue;
            }
            entries.add(new Entry(p.lineNo(), fn, names, classes, ruleKey, because, p.raw()));
        }
    }

    // ------------------------------------------------------------------------------------------------
    // 2. match
    // ------------------------------------------------------------------------------------------------
    static void begin(Policy.GateInput gi) {
        unevaluated = pendingUnevaluated;
        pendingUnevaluated = new HashSet<>();
        directBy.clear(); nestedBy.clear(); remaining.clear();
        acceptedRows = 0;
        accepted = null;
        staleLinesLast = new TreeSet<>();
        twinNames = new HashSet<>();
        callersOf = new HashMap<>();
        if (entries.isEmpty() && !forceTwins) return;
        for (var e : gi.edges().entrySet()) {
            String caller = gi.disp(e.getKey());
            for (String callee : e.getValue()) callersOf.computeIfAbsent(gi.disp(callee), x -> new TreeSet<>()).add(caller);
        }
        // (hash, fn) TWINS: two units of this run sharing a name. The scan route gates one analysis world
        // (a name is a unit), the report route keys by hash, so >1 key under a name IS the twin case.
        Map<String, Set<String>> byName = new HashMap<>();
        Set<String> keys = new HashSet<>(gi.inferred().keySet());
        keys.addAll(gi.edges().keySet());
        keys.removeAll(gi.synthetic());
        for (String k : keys) byName.computeIfAbsent(gi.disp(k), x -> new HashSet<>()).add(k);
        for (var e : byName.entrySet()) if (e.getValue().size() > 1) twinNames.add(e.getKey());
    }

    private static boolean usable(Entry e) {
        return !unevaluated.contains(e.ruleKey()) && !twinNames.contains(e.fn());
    }

    private static boolean covers(Entry e, Row r) {
        for (String x : r.effects) {
            if (x.equals("Unknown")) {
                if (!e.effects().contains("Unknown") || e.classes() == null) return false;
                // an Unknown whose classes are not determinable is NOT covered by any filter (fail closed)
                if (r.classes.isEmpty() || !e.classes().containsAll(r.classes)) return false;
            } else if (!e.effects().contains(x)) {
                return false;
            }
        }
        return true;
    }

    /** This run's call graph, inverted and by display name: callee -> the units that edge it. It is how a lambda
     *  finds WHICH overload encloses it: javac's {@code lambda$over$1} does not say, but the enclosing method is the
     *  one that holds the invokedynamic, and the scan edges exactly that method to the lambda unit. */
    private static Map<String, Set<String>> callersOf = new HashMap<>();

    private static final Pattern LAMBDA = Pattern.compile("^(.*)\\.lambda\\$(.+)\\$\\d+$");

    /** Candidate FQ names of the method a javac lambda is lexically inside (§6.2 nested-unit rule). */
    private static List<String> enclosingOf(String fn) {
        Matcher m = LAMBDA.matcher(fn);
        if (!m.matches()) return List.of();
        String cls = m.group(1), meth = m.group(2);
        List<String> out = new ArrayList<>();
        if (meth.equals("new")) out.add(cls + ".<init>");
        else if (meth.equals("static")) out.add(cls + ".<clinit>");
        else out.add(cls + "." + meth);
        // An overloaded method or constructor is reported WITH its parameter list, so the bare name above never
        // matches it. Take the overload from the call graph instead of guessing: only a unit that edges THIS
        // lambda and is spelled `cls.meth(...)` (or, for a lambda in a lambda, another lambda of the class, so the
        // climb can continue) is a candidate. An overload that does not enclose the lambda has no such edge, so an
        // entry on it covers nothing here (fail-closed); the subset conditions in settle() still apply unchanged.
        String head = meth.equals("new") ? cls + ".<init>(" : meth.equals("static") ? null : cls + "." + meth + "(";
        for (String caller : callersOf.getOrDefault(fn, Set.of())) {
            boolean lam = LAMBDA.matcher(caller).matches() && caller.startsWith(cls + ".lambda$");
            if ((head != null && caller.startsWith(head)) || lam) { if (!out.contains(caller)) out.add(caller); }
        }
        return out;
    }

    /** Decide without emitting — for the advisory verbs, which only need to know WHICH units are accepted. */
    static void settleDry(List<Row> rows) {
        List<Row> inert = new ArrayList<>();
        for (Row r : rows) inert.add(new Row(r.ruleKey, r.code, r.name, r.hash, r.effects, r.classes, () -> {}));
        settle(inert);
    }

    /** ⟨0.41⟩ For {@code accepts}: per entry line, the rows that entry accepted DIRECTLY in the last gate (a copy). */
    static Map<Integer, List<Row>> directSnapshot() {
        Map<Integer, List<Row>> m = new HashMap<>();
        for (var e : directBy.entrySet()) m.put(e.getKey(), new ArrayList<>(e.getValue()));
        return m;
    }

    /** ⟨0.41⟩ For {@code accepts}: the names two units of the last gate shared (the (hash, fn) twin case). */
    static Set<String> twinSnapshot() { return new HashSet<>(twinNames); }

    /** Names of units a direct or nested acceptance covered in the last {@link #begin}…settle cycle. */
    static Set<String> acceptedNames() {
        Set<String> s = new TreeSet<>();
        for (var l : directBy.values()) for (Row r : l) s.add(r.name);
        for (var l : nestedBy.values()) for (Object[] n : l) s.add(((Row) n[0]).name);
        return s;
    }

    /** Decide one producer's rows; emit the survivors in order; return how many were emitted. */
    static int settle(List<Row> rows) {
        if (entries.isEmpty()) {
            for (Row r : rows) r.emit.run();
            return rows.size();
        }
        boolean[] acc = new boolean[rows.size()];
        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            for (Entry e : entries) {
                if (!usable(e) || !e.ruleKey().equals(r.ruleKey) || !e.fn().equals(r.name)) continue;
                if (covers(e, r)) {
                    acc[i] = true;
                    directBy.computeIfAbsent(e.line(), k -> new ArrayList<>()).add(r);
                }
            }
        }
        // nested-unit rule: the enclosing method's row under the SAME rule line must be accepted by the
        // SAME entry in THIS run, and the nested row's effects must be a subset of it.
        for (int i = 0; i < rows.size(); i++) {
            if (acc[i]) continue;
            Row v = rows.get(i);
            String cur = v.name;
            for (int depth = 0; depth < 8; depth++) {
                List<String> enc = enclosingOf(cur);
                if (enc.isEmpty()) break;
                String next = null;
                for (String cand : enc) {
                    for (Entry e : entries) {
                        if (!usable(e) || !e.ruleKey().equals(v.ruleKey) || !e.fn().equals(cand)) continue;
                        List<Row> mine = directBy.getOrDefault(e.line(), List.of());
                        for (Row u : mine) {
                            if (u.name.equals(cand) && u.ruleKey.equals(v.ruleKey) && u.effects.containsAll(v.effects)) {
                                acc[i] = true;
                                nestedBy.computeIfAbsent(e.line(), k -> new ArrayList<>()).add(new Object[]{v, u});
                            }
                        }
                    }
                    if (next == null) next = cand;
                }
                if (acc[i] || next == null) break;
                cur = next;                      // a lambda inside a lambda: climb to the next positional parent
            }
        }
        int emitted = 0;
        for (int i = 0; i < rows.size(); i++) {
            if (acc[i]) acceptedRows++;
            else { remaining.add(rows.get(i)); rows.get(i).emit.run(); emitted++; }
        }
        return emitted;
    }

    // ------------------------------------------------------------------------------------------------
    // 3. statuses, stale rows, the verdict key
    // ------------------------------------------------------------------------------------------------
    /** Emits one AS-EFF-012 per stale entry and builds {@link #accepted}. Returns the rows emitted. */
    static int finish() {
        if (entries.isEmpty()) return 0;
        int stale = 0;
        List<Map<String, Object>> items = new ArrayList<>();
        for (Entry e : entries) {
            boolean forbid = e.effects().isEmpty();
            String code = forbid ? "AS-EFF-009" : "AS-EFF-006";
            if (unevaluated.contains(e.ruleKey())) {
                items.add(item(e, code, e.fn(), null, e.effects(), "unjudged", null));
                System.err.println("candor-java: policy line " + e.line() + " (`" + e.raw() + "`) is UNJUDGED — its rule `"
                        + e.ruleKey() + "` could not be evaluated on this route, so nothing was accepted by it. Gate at scan time "
                        + "(`candor <classes> --policy …`) to judge it.");
                continue;
            }
            if (twinNames.contains(e.fn())) {
                items.add(item(e, code, e.fn(), null, e.effects(), "ambiguous", null));
                System.err.println("candor-java: policy line " + e.line() + " (`" + e.raw() + "`) is AMBIGUOUS — two units in this run "
                        + "are named `" + e.fn() + "` with different hashes, so it accepts NEITHER. Gate the modules separately "
                        + "(one policy file per separately-gated module) so each name is one unit.");
                continue;
            }
            List<Row> direct = directBy.getOrDefault(e.line(), List.of());
            if (!direct.isEmpty()) {
                Row r = direct.get(0);
                items.add(item(e, r.code, r.name, r.hash, new TreeSet<>(r.effects), "accepted", null));
                for (Object[] n : nestedBy.getOrDefault(e.line(), List.of())) {
                    Row v = (Row) n[0];
                    items.add(item(e, v.code, v.name, v.hash, new TreeSet<>(v.effects), "accepted", e.fn()));
                }
                continue;
            }
            Row over = null;
            for (Row r : remaining) if (r.ruleKey.equals(e.ruleKey()) && r.name.equals(e.fn())) { over = r; break; }
            if (over != null) {
                items.add(item(e, code, e.fn(), null, e.effects(), "exceeded", null));
                System.err.println("candor-java: policy line " + e.line() + " (`" + e.raw() + "`) no longer covers `" + e.fn()
                        + "`: it now performs { " + String.join(", ", over.effects) + " } under `" + e.ruleKey() + "`, more than the "
                        + "{ " + String.join(", ", e.effects()) + " } accepted. The violation stays red. Review the new behaviour; "
                        + "if it is intended, widen the entry to list it, otherwise fix the code.");
                continue;
            }
            stale++;
            staleLinesLast.add(e.line());
            Candor.diagUnit(DiagnosticCode.AS_EFF_012, EffectSet.ofNames(e.effects()).toNames(), List.of(), List.of(), "",
                    STALE_FMT, e.fn(), e.line(), e.raw(), e.ruleKey(), e.line());
        }
        items.sort((a, b) -> {
            int c = Integer.compare((int) a.get("line"), (int) b.get("line"));
            if (c != 0) return c;
            c = Query.BY_CODE_POINT.compare((String) a.get("fn"), (String) b.get("fn"));
            if (c != 0) return c;
            return Query.BY_CODE_POINT.compare((String) a.getOrDefault("hash", ""), (String) b.getOrDefault("hash", ""));
        });
        accepted = items;
        return stale;
    }

    private static final String STALE_FMT = "`%s` has a STALE acceptance — policy line %d (`%s`) matched no violation of `%s`. "
            + "Delete line %d: left in place it would accept whatever a later edit puts under that key";

    /** ⟨0.41⟩ The STALE entries of the last {@link #begin}…{@link #settleDry} cycle, as {fn, AS-EFF-012 message} pairs in
     *  policy order — for the advisory verbs, which must not lose a finding the gate exits 1 on (§6.2: {@code fix-gate}
     *  carries them as {@code staleAccepts}). The SAME classification as {@link #finish}: an entry is stale unless it was
     *  unjudged, ambiguous, matched a row, or is exceeded by a remaining row of its rule and fn. */
    static List<String[]> staleDry() {
        List<String[]> out = new ArrayList<>();
        for (Entry e : entries) {
            if (unevaluated.contains(e.ruleKey()) || twinNames.contains(e.fn())) continue;
            if (!directBy.getOrDefault(e.line(), List.of()).isEmpty()) continue;
            boolean over = false;
            for (Row r : remaining) if (r.ruleKey.equals(e.ruleKey()) && r.name.equals(e.fn())) { over = true; break; }
            if (over) continue;
            out.add(new String[]{e.fn(), String.format(STALE_FMT, e.fn(), e.line(), e.raw(), e.ruleKey(), e.line())});
        }
        return out;
    }

    private static Map<String, Object> item(Entry e, String code, String fn, String hash,
                                            Collection<String> effects, String status, String enclosing) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rule", code);
        m.put("fn", fn);
        if (hash != null && !hash.isEmpty()) m.put("hash", hash);
        m.put("effects", EffectSet.ofNames(effects).toNames());
        m.put("line", e.line());
        m.put("policyRule", e.ruleKey());
        m.put("because", e.because());
        m.put("status", status);
        if (enclosing != null) m.put("enclosing", enclosing);
        return m;
    }

    /** The human-channel line SPEC §6.2 requires on every run with at least one accepted row. */
    static void announce(int newViolations) {
        if (acceptedRows > 0)
            System.err.println("candor-java: " + acceptedRows + " violation(s) accepted by policy; " + newViolations + " new");
    }

    static int acceptedRows() { return acceptedRows; }

    /** Reasons used by tests. */
    static Map<String, Integer> debugCounts() {
        Map<String, Integer> m = new TreeMap<>();
        m.put("entries", entries.size());
        m.put("acceptedRows", acceptedRows);
        return m;
    }
}
