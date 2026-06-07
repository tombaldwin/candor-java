package candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Read-only queries over a candor report (candor-spec §2): show / where / callers / map / diff.
 * The analyzer ({@link Candor}) writes the report; these answer questions about it WITHOUT
 * re-analysis — the sibling of the Rust impl's {@code candor-query}. Each takes an optional
 * {@code --json} flag for machine-readable output (the form an agent / MCP server consumes); the
 * default is the human view. Accepts the v0.2 {@code { candor, functions }} envelope and the legacy
 * v0.1 bare array.
 */
public final class Query {
    static final Set<String> COMMANDS = Set.of("show", "where", "callers", "map", "diff");
    static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();

    /** One report entry (only the fields the queries read; gson ignores the rest). */
    static final class Fn {
        String fn = "";
        List<String> inferred = List.of();
        List<String> direct = List.of();
        List<String> calls = List.of();
        List<String> fs = List.of();
        boolean unresolved;
    }

    static List<Fn> load(String path) throws Exception {
        JsonElement root = JsonParser.parseString(Files.readString(Path.of(path)));
        // v0.2 self-describing envelope { candor, functions:[...] } OR legacy v0.1 bare array [...].
        JsonArray arr = root.isJsonObject()
                ? root.getAsJsonObject().getAsJsonArray("functions")
                : (root.isJsonArray() ? root.getAsJsonArray() : null);
        if (arr == null) return List.of();
        List<Fn> fns = new Gson().fromJson(arr, new TypeToken<List<Fn>>() {}.getType());
        for (Fn f : fns) { // gson leaves absent optional arrays null — normalize
            if (f.inferred == null) f.inferred = List.of();
            if (f.direct == null) f.direct = List.of();
            if (f.calls == null) f.calls = List.of();
            if (f.fs == null) f.fs = List.of();
        }
        fns.sort(Comparator.comparing(f -> f.fn));
        return fns;
    }

    static int run(String[] args) {
        String cmd = args[0];
        boolean json = false;
        List<String> pos = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--json")) json = true;
            else pos.add(args[i]);
        }
        if (pos.isEmpty()) {
            System.err.println("usage: candor " + cmd + " <report.json> [arg] [--json]");
            return 2;
        }
        List<Fn> fns;
        try {
            fns = load(pos.get(0));
        } catch (Exception e) {
            System.err.println("candor: cannot read report " + pos.get(0));
            return 2;
        }
        String arg = pos.size() > 1 ? pos.get(1) : null;
        return switch (cmd) {
            case "show" -> show(fns, arg, json);
            case "where" -> where(fns, arg, json);
            case "callers" -> callers(fns, arg, json);
            case "map" -> map(fns, json);
            case "diff" -> diff(fns, arg, json);
            default -> 2;
        };
    }

    static int usage(String u) {
        System.err.println("usage: candor " + u);
        return 2;
    }

    static List<String> sorted(List<String> l) {
        List<String> x = new ArrayList<>(l);
        Collections.sort(x);
        return x;
    }

    static void emit(Object o) {
        System.out.println(JSON.toJson(o));
    }

    /** A function's effects, instant — `*` marks an effect performed in its own body. */
    static int show(List<Fn> fns, String q, boolean json) {
        if (q == null) return usage("show <report.json> <function-substring> [--json]");
        List<Fn> hits = fns.stream().filter(f -> f.fn.contains(q)).collect(Collectors.toList());
        if (json) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Fn f : hits) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("fn", f.fn);
                m.put("inferred", sorted(f.inferred));
                m.put("direct", sorted(f.direct));
                if (!f.fs.isEmpty()) m.put("fs", f.fs);
                m.put("unresolved", f.unresolved);
                out.add(m);
            }
            emit(out);
            return 0;
        }
        if (hits.isEmpty()) {
            System.out.println("candor: no effectful function matching `" + q + "` (pure functions are omitted).");
            return 0;
        }
        int w = hits.stream().mapToInt(f -> f.fn.length()).max().orElse(0);
        for (Fn f : hits) {
            Set<String> direct = new HashSet<>(f.direct);
            String parts = sorted(f.inferred).stream()
                    .map(x -> {
                        String star = direct.contains(x) ? "*" : "";
                        if (x.equals("Fs") && !f.fs.isEmpty()) return "Fs" + star + "(" + String.join(",", f.fs) + ")";
                        return x + star;
                    })
                    .collect(Collectors.joining(" "));
            String unk = f.unresolved ? "  ⚠ unresolved (set may be incomplete)" : "";
            System.out.printf("  %-" + w + "s  { %s }%s%n", f.fn, parts, unk);
        }
        System.out.println("  (* = performed in the function's own body; unmarked = via a callee)");
        return 0;
    }

    /** Which functions perform an effect — direct sources split from inheritors. */
    static int where(List<Fn> fns, String eff, boolean json) {
        if (eff == null) return usage("where <report.json> <Effect> [--json]");
        List<String> direct = fns.stream().filter(f -> f.direct.contains(eff)).map(f -> f.fn).sorted().toList();
        List<String> inherit = fns.stream()
                .filter(f -> f.inferred.contains(eff) && !f.direct.contains(eff)).map(f -> f.fn).sorted().toList();
        if (json) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("effect", eff);
            m.put("directly", direct);
            m.put("inherited", inherit);
            emit(m);
            return 0;
        }
        if (direct.isEmpty() && inherit.isEmpty()) {
            System.out.println("candor: no function performs " + eff + " in the report.");
            return 0;
        }
        System.out.println((direct.size() + inherit.size()) + " function(s) perform " + eff + ":");
        if (!direct.isEmpty()) {
            System.out.println("  directly (" + direct.size() + "):");
            direct.forEach(s -> System.out.println("    " + s));
        }
        if (!inherit.isEmpty()) {
            System.out.println("  inherit it via a callee (" + inherit.size() + "):");
            inherit.forEach(s -> System.out.println("    " + s));
        }
        return 0;
    }

    /** Who calls a function — inverts the report's `calls` effect graph (no re-analysis). */
    static int callers(List<Fn> fns, String q, boolean json) {
        if (q == null) return usage("callers <report.json> <function-substring> [--json]");
        TreeMap<String, TreeSet<String>> hits = new TreeMap<>(); // callee -> its callers
        for (Fn f : fns) {
            for (String callee : f.calls) {
                if (callee.contains(q)) hits.computeIfAbsent(callee, k -> new TreeSet<>()).add(f.fn);
            }
        }
        if (json) {
            Map<String, List<String>> out = new LinkedHashMap<>();
            hits.forEach((k, v) -> out.put(k, new ArrayList<>(v)));
            emit(out);
            return 0;
        }
        if (hits.isEmpty()) {
            System.out.println("candor: nothing matching `" + q
                    + "` is called by an effectful function (callers of pure functions aren't tracked).");
            return 0;
        }
        for (var e : hits.entrySet()) {
            System.out.println("  " + e.getKey() + "  ← called by " + e.getValue().size() + ":");
            for (String c : e.getValue()) System.out.println("      " + c);
        }
        return 0;
    }

    /** A class -> effects overview of the whole report, most-effectful first. */
    static int map(List<Fn> fns, boolean json) {
        Map<String, TreeSet<String>> mods = new HashMap<>();
        Map<String, Integer> counts = new HashMap<>();
        for (Fn f : fns) {
            int dot = f.fn.lastIndexOf('.');
            String mod = dot > 0 ? f.fn.substring(0, dot) : f.fn; // declaring class
            mods.computeIfAbsent(mod, k -> new TreeSet<>())
                    .addAll(f.inferred.stream().filter(x -> !x.equals("Unknown")).toList());
            counts.merge(mod, 1, Integer::sum);
        }
        if (json) {
            Map<String, Object> out = new TreeMap<>();
            for (var m : mods.keySet()) {
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("effects", new ArrayList<>(mods.get(m)));
                v.put("functions", counts.get(m));
                out.put(m, v);
            }
            emit(out);
            return 0;
        }
        if (mods.isEmpty()) {
            System.out.println("candor: no effectful functions in the report.");
            return 0;
        }
        int total = counts.values().stream().mapToInt(i -> i).sum();
        System.out.println("candor map — " + total + " effectful functions across " + mods.size() + " class(es)\n");
        int w = mods.keySet().stream().mapToInt(String::length).max().orElse(0);
        mods.keySet().stream()
                .sorted((a, b) -> counts.get(b).equals(counts.get(a)) ? a.compareTo(b) : counts.get(b) - counts.get(a))
                .forEach(m -> {
                    int n = counts.get(m);
                    System.out.printf("  %-" + w + "s  { %s }  (%d fn%s)%n",
                            m, String.join(" ", mods.get(m)), n, n == 1 ? "" : "s");
                });
        return 0;
    }

    /** Per-function effect delta vs a baseline report (+gained / -lost). */
    static int diff(List<Fn> cur, String basePath, boolean json) {
        if (basePath == null) return usage("diff <report.json> <baseline.json> [--json]");
        List<Fn> base;
        try {
            base = load(basePath);
        } catch (Exception e) {
            System.out.println("candor: cannot read baseline " + basePath);
            return 2;
        }
        Map<String, Set<String>> b = base.stream().collect(Collectors.toMap(f -> f.fn, f -> new HashSet<>(f.inferred), (x, y) -> x));
        Map<String, Set<String>> c = cur.stream().collect(Collectors.toMap(f -> f.fn, f -> new HashSet<>(f.inferred), (x, y) -> x));
        TreeSet<String> all = new TreeSet<>();
        all.addAll(b.keySet());
        all.addAll(c.keySet());
        List<Map<String, Object>> changes = new ArrayList<>();
        for (String fn : all) {
            Set<String> bi = b.getOrDefault(fn, Set.of());
            Set<String> ci = c.getOrDefault(fn, Set.of());
            List<String> gained = ci.stream().filter(x -> !bi.contains(x)).sorted().toList();
            List<String> lost = bi.stream().filter(x -> !ci.contains(x)).sorted().toList();
            if (gained.isEmpty() && lost.isEmpty()) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("fn", fn);
            m.put("gained", gained);
            m.put("lost", lost);
            m.put("status", !c.containsKey(fn) ? "removed" : (!b.containsKey(fn) ? "new" : "changed"));
            changes.add(m);
        }
        if (json) {
            emit(changes);
            return 0;
        }
        if (changes.isEmpty()) {
            System.out.println("candor: no effect changes vs " + basePath + ".");
            return 0;
        }
        for (Map<String, Object> m : changes) {
            @SuppressWarnings("unchecked")
            List<String> gained = (List<String>) m.get("gained");
            @SuppressWarnings("unchecked")
            List<String> lost = (List<String>) m.get("lost");
            List<String> parts = new ArrayList<>();
            gained.forEach(x -> parts.add("+" + x));
            lost.forEach(x -> parts.add("-" + x));
            String st = (String) m.get("status");
            String tag = st.equals("removed") ? "  (removed fn)" : (st.equals("new") ? "  (new fn)" : "");
            System.out.println("  " + m.get("fn") + tag + "   { " + String.join(" ", parts) + " }");
        }
        return 0;
    }

    private Query() {}
}
