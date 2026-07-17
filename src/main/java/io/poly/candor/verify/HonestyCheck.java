package io.poly.candor.verify;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * ⟨verify⟩ The checker of the JVM honesty oracle — a faithful port of candor-ts/verify-core.mjs. Given a
 * candor report (per-fn inferred effects) and a runtime trace (effect-bearing calls attributed to the
 * enclosing fn at transform time), it decides the honesty invariant per EXECUTED function:
 *
 * <pre>   observed(f) ⊆ inferred(f)     OR     Unknown ∈ inferred(f)</pre>
 *
 * and classifies each executed fn:
 * <ul>
 *   <li><b>sound-complete-ok</b> — Unknown ∉ inferred, observed ⊆ inferred (held tightly);</li>
 *   <li><b>disclosed-partial</b> — Unknown ∈ inferred (held by disclosure); of which "Unknown-load-bearing"
 *       when observed ⊄ (inferred ∖ {Unknown}) — the disclosure actually mattered;</li>
 *   <li><b>VIOLATION</b> — Unknown ∉ inferred, observed ⊄ inferred — a FALSE ALL-CLEAR, the cardinal sin.</li>
 * </ul>
 *
 * <p>A fn ABSENT from the report is a claim of purity (inferred = ∅) — so a silently-dropped effectful fn
 * surfaces here as a violation, exactly the class candor exists to prevent.
 *
 * <p>REFINEMENT-AWARE (matching verify-core): {@code Llm} and {@code Db} are refinements of {@code Net}
 * (an Llm/Db call IS a Net call). So an observed Llm/Db is COVERED if Llm/Db OR Net is inferred; a missing
 * refinement is not a violation, only a missing BASE effect is.
 *
 * <p>Independence: this reads only the report JSON and the trace — it never consults candor's classifier.
 */
public final class HonestyCheck {

    private HonestyCheck() {}

    private static final String UNKNOWN = "Unknown";

    // The `direct` scope = the syscall-parity headline (what a mechanism-independent trace witnesses).
    // `all` additionally covers the language-level effects the JDK map wraps at the boundary.
    private static final List<String> DIRECT_SCOPE = List.of("Net", "Fs", "Exec");
    private static final List<String> ALL_EXTRA = List.of("Env", "Clock", "Rand", "Llm", "Db");

    // Effect refinements: an observed refinement is covered if the refinement OR its base is inferred.
    private static final Map<String, String> BASE = Map.of("Llm", "Net", "Db", "Net");

    private static Set<String> scopeSet(String scope) {
        Set<String> s = new TreeSet<>(DIRECT_SCOPE);
        if ("all".equals(scope)) s.addAll(ALL_EXTRA);
        return s;
    }

    private static boolean covered(String e, Set<String> inferred) {
        return inferred.contains(e) || (BASE.containsKey(e) && inferred.contains(BASE.get(e)));
    }

    /** obs ⊆ inferred (up to refinement). */
    private static boolean subset(Set<String> obs, Set<String> inferred) {
        for (String e : obs) if (!covered(e, inferred)) return false;
        return true;
    }

    /** The genuinely-escaped effects (observed but not covered by inferred). */
    private static Set<String> escaped(Set<String> obs, Set<String> inferred) {
        Set<String> out = new TreeSet<>();
        for (String e : obs) if (!covered(e, inferred)) out.add(e);
        return out;
    }

    /** report `{functions:[{fn,inferred}]}` (or a bare array) → Map fn → Set(effects). Absent ⇒ ∅ (pure). */
    public static Map<String, Set<String>> reportEffects(JsonElement report) {
        JsonArray fns;
        if (report.isJsonArray()) {
            fns = report.getAsJsonArray();
        } else {
            JsonObject o = report.getAsJsonObject();
            fns = o.has("functions") && o.get("functions").isJsonArray()
                    ? o.getAsJsonArray("functions") : new JsonArray();
        }
        Map<String, Set<String>> m = new LinkedHashMap<>();
        for (JsonElement el : fns) {
            JsonObject f = el.getAsJsonObject();
            if (!f.has("fn")) continue;
            Set<String> eff = new TreeSet<>();
            if (f.has("inferred") && f.get("inferred").isJsonArray()) {
                for (JsonElement x : f.getAsJsonArray("inferred")) eff.add(x.getAsString());
            }
            m.put(f.get("fn").getAsString(), eff);
        }
        return m;
    }

    /** trace events (fn → observed effects) filtered to scope. Executed-but-effect-free fns still count. */
    public static Map<String, Set<String>> observedByFn(List<TraceEvent> events, String scope) {
        Set<String> allowed = scopeSet(scope);
        Map<String, Set<String>> obs = new TreeMap<>();
        for (TraceEvent ev : events) {
            if (ev == null || ev.fn == null) continue;
            Set<String> set = obs.computeIfAbsent(ev.fn, k -> new TreeSet<>());
            if (ev.effect != null && allowed.contains(ev.effect)) set.add(ev.effect);
        }
        return obs;
    }

    /** A single attributed effect observation. */
    public static final class TraceEvent {
        public final String fn;
        public final String effect;
        public TraceEvent(String fn, String effect) { this.fn = fn; this.effect = effect; }
    }

    /** A cardinal-sin violation record (mirrors verify-core's `{fn, observed, inferred, escaped}`). */
    public static final class Violation {
        public final String fn;
        public final List<String> observed;
        public final List<String> inferred;
        public final List<String> escaped;
        Violation(String fn, Set<String> observed, Set<String> inferred, Set<String> escaped) {
            this.fn = fn;
            this.observed = new ArrayList<>(observed);
            this.inferred = new ArrayList<>(inferred);
            this.escaped = new ArrayList<>(escaped);
        }
    }

    /** One executed fn's verdict (mirrors verify-core's `rows`): sound-complete-ok / disclosed-partial / VIOLATION. */
    public static final class Row {
        public final String fn;
        public final String verdict;
        public final List<String> observed;
        public final List<String> inferred;
        Row(String fn, String verdict, Set<String> observed, Set<String> inferred) {
            this.fn = fn;
            this.verdict = verdict;
            this.observed = new ArrayList<>(observed);
            this.inferred = new ArrayList<>(inferred);
        }
    }

    /** The full result: metrics + per-fn rows + violations. */
    public static final class Result {
        public final String scope;
        public final List<String> effectsInScope;
        public final int executedFunctionsChecked;
        public final int soundCompleteOk;
        public final int disclosedPartial;
        public final int disclosedUnknownLoadBearing;
        public final int cardinalSinViolations;
        public final boolean honestyInvariantHolds;
        public final List<Row> rows;
        public final List<Violation> violations;
        // Set by the CLI (not the pure check): false when the run could not soundly witness every effect — no
        // callgraph sidecar (pure classes uninstrumented) or torn trace lines. Mirrors the ts arm; drives exit 2.
        public boolean attributionComplete = true;
        public String attributionNote = null;

        Result(String scope, Set<String> allowed, int checked, int clean, int disclosed,
                int loadBearing, List<Row> rows, List<Violation> violations) {
            this.scope = scope;
            this.effectsInScope = new ArrayList<>(allowed);
            this.executedFunctionsChecked = checked;
            this.soundCompleteOk = clean;
            this.disclosedPartial = disclosed;
            this.disclosedUnknownLoadBearing = loadBearing;
            this.cardinalSinViolations = violations.size();
            this.honestyInvariantHolds = violations.isEmpty();
            this.rows = rows;
            this.violations = violations;
        }
    }

    /**
     * The invariant check. {@code reportMap}/{@code observedMap} are fn → Set(effects). A VIOLATION is a fn
     * that ran effects its COMPLETE (no-Unknown) signature didn't include — the cardinal sin.
     */
    public static Result honestyCheck(Map<String, Set<String>> reportMap,
            Map<String, Set<String>> observedMap, String scope) {
        Set<String> allowed = scopeSet(scope);
        List<Violation> violations = new ArrayList<>();
        List<Row> rows = new ArrayList<>();
        int clean = 0, disclosed = 0, loadBearing = 0;
        // observedMap is a TreeMap → iteration is already sorted by fn (matches verify-core's sort).
        for (Map.Entry<String, Set<String>> e : observedMap.entrySet()) {
            String fn = e.getKey();
            Set<String> inferred = reportMap.getOrDefault(fn, new TreeSet<>()); // absent ⇒ ∅ (claimed pure)
            Set<String> obs = new TreeSet<>();
            for (String o : e.getValue()) if (allowed.contains(o)) obs.add(o);
            String verdict;
            if (inferred.contains(UNKNOWN)) {
                disclosed++;
                verdict = "disclosed-partial";
                Set<String> tight = new TreeSet<>(inferred);
                tight.remove(UNKNOWN);
                if (!subset(obs, tight)) loadBearing++; // the Unknown was doing real work
            } else if (subset(obs, inferred)) {
                clean++;
                verdict = "sound-complete-ok";
            } else {
                verdict = "VIOLATION";
                violations.add(new Violation(fn, obs, inferred, escaped(obs, inferred)));
            }
            rows.add(new Row(fn, verdict, obs, inferred));
        }
        return new Result(scope, allowed, observedMap.size(), clean, disclosed, loadBearing, rows, violations);
    }
}
