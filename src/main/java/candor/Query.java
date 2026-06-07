package candor;

import com.google.gson.Gson;
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
 * re-analysis — the sibling of the Rust impl's {@code candor-query}. They read the report's own
 * fields: {@code inferred}/{@code direct} for show/where/map/diff, and the {@code calls} effect graph
 * for callers. Accepts the v0.2 {@code { candor, functions }} envelope and the legacy v0.1 array.
 */
public final class Query {
    static final Set<String> COMMANDS = Set.of("show", "where", "callers", "map", "diff");

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
        if (args.length < 2) {
            System.err.println("usage: candor " + cmd + " <report.json> [arg]");
            return 2;
        }
        List<Fn> fns;
        try {
            fns = load(args[1]);
        } catch (Exception e) {
            System.err.println("candor: cannot read report " + args[1]);
            return 2;
        }
        String arg = args.length > 2 ? args[2] : null;
        return switch (cmd) {
            case "show" -> show(fns, arg);
            case "where" -> where(fns, arg);
            case "callers" -> callers(fns, arg);
            case "map" -> map(fns);
            case "diff" -> diff(fns, arg);
            default -> 2;
        };
    }

    static int usage(String u) {
        System.err.println("usage: candor " + u);
        return 2;
    }

    /** A function's effects, instant — `*` marks an effect performed in its own body. */
    static int show(List<Fn> fns, String q) {
        if (q == null) return usage("show <report.json> <function-substring>");
        List<Fn> hits = fns.stream().filter(f -> f.fn.contains(q)).collect(Collectors.toList());
        if (hits.isEmpty()) {
            System.out.println("candor: no effectful function matching `" + q + "` (pure functions are omitted).");
            return 0;
        }
        int w = hits.stream().mapToInt(f -> f.fn.length()).max().orElse(0);
        for (Fn f : hits) {
            Set<String> direct = new HashSet<>(f.direct);
            String parts = f.inferred.stream().sorted()
                    .map(x -> {
                        String star = direct.contains(x) ? "*" : "";
                        // Refine Fs with its read/write detail when known: `Fs*(write)`.
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
    static int where(List<Fn> fns, String eff) {
        if (eff == null) return usage("where <report.json> <Effect>");
        List<String> direct = fns.stream().filter(f -> f.direct.contains(eff)).map(f -> f.fn).sorted().toList();
        List<String> inherit = fns.stream()
                .filter(f -> f.inferred.contains(eff) && !f.direct.contains(eff)).map(f -> f.fn).sorted().toList();
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
    static int callers(List<Fn> fns, String q) {
        if (q == null) return usage("callers <report.json> <function-substring>");
        TreeMap<String, TreeSet<String>> hits = new TreeMap<>(); // callee -> its callers
        for (Fn f : fns) {
            for (String callee : f.calls) {
                if (callee.contains(q)) hits.computeIfAbsent(callee, k -> new TreeSet<>()).add(f.fn);
            }
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
    static int map(List<Fn> fns) {
        Map<String, TreeSet<String>> mods = new HashMap<>();
        Map<String, Integer> counts = new HashMap<>();
        for (Fn f : fns) {
            int dot = f.fn.lastIndexOf('.');
            String mod = dot > 0 ? f.fn.substring(0, dot) : f.fn; // declaring class
            mods.computeIfAbsent(mod, k -> new TreeSet<>())
                    .addAll(f.inferred.stream().filter(x -> !x.equals("Unknown")).toList());
            counts.merge(mod, 1, Integer::sum);
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
    static int diff(List<Fn> cur, String basePath) {
        if (basePath == null) return usage("diff <report.json> <baseline.json>");
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
        boolean any = false;
        for (String fn : all) {
            Set<String> bi = b.getOrDefault(fn, Set.of());
            Set<String> ci = c.getOrDefault(fn, Set.of());
            List<String> gained = ci.stream().filter(x -> !bi.contains(x)).sorted().toList();
            List<String> lost = bi.stream().filter(x -> !ci.contains(x)).sorted().toList();
            if (gained.isEmpty() && lost.isEmpty()) continue;
            any = true;
            List<String> parts = new ArrayList<>();
            gained.forEach(x -> parts.add("+" + x));
            lost.forEach(x -> parts.add("-" + x));
            String tag = !c.containsKey(fn) ? "  (removed fn)" : (!b.containsKey(fn) ? "  (new fn)" : "");
            System.out.println("  " + fn + tag + "   { " + String.join(" ", parts) + " }");
        }
        if (!any) System.out.println("candor: no effect changes vs " + basePath + ".");
        return 0;
    }

    private Query() {}
}
