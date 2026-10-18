package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1203 — THE EQUALITY/HASHING SITE TABLE. Every {@code x*} hands an EXACT {@code new EqEff} (whose
 * {@code equals}/{@code hashCode} write a file) to a JDK call that runs it. EXECUTED on JDK 21 (fixture
 * {@code javaagent-v071/f11}, package {@code vx}, driver {@code vx.D}): every {@code x*} wrote the file except
 * {@code x30MapReplace} (a {@code replace} on an EMPTY map never hashes; {@code x37ReplaceNonEmpty} does), and every
 * {@code kx*} wrote nothing. On 0.40.12 the {@link #NEWLY} members were absent under {@code deny Fs Unknown <fn>}.
 */
class HashingR1203Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1201/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String TYPES = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "final class EqEff { final int v; EqEff(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof EqEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; } }\n"
            + "final class EqPure { final int v; EqPure(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { return o instanceof EqPure e && e.v == v; }\n"
            + "  @Override public int hashCode() { return v; } }\n";

    static final String MAIN = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "import java.util.concurrent.*;\n"
            + "import java.util.stream.*;\n"
            + "/** Every key/element here is an EXACT `new EqEff` (or a List<EqEff>): a silent row is a SITE the engine does not model. */\n"
            + "public class N {\n"
            + "  public static void x01MapPut() { Map<EqEff, Integer> m = new HashMap<>(); m.put(new EqEff(1), 1); }\n"
            + "  public static void x02SetAdd() { Set<EqEff> s = new HashSet<>(); s.add(new EqEff(1)); }\n"
            + "  public static void x03ListHash() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.hashCode(); }\n"
            + "  public static void x04HashSetCopy() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.add(new EqEff(2)); new HashSet<>(l); }\n"
            + "  public static void x05Contains() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.contains(new EqEff(1)); }\n"
            + "  public static void x06ObjectsHash() { Objects.hash(new EqEff(1)); }\n"
            + "  public static void x07ObjectsEquals() { Objects.equals(new EqEff(1), new EqEff(2)); }\n"
            + "  public static void x08ObjectsHashCode() { Objects.hashCode(new EqEff(1)); }\n"
            + "  public static void x09ComputeIfAbsent() { Map<EqEff, Integer> m = new HashMap<>(); m.computeIfAbsent(new EqEff(1), k -> 1); }\n"
            + "  public static void x10Merge() { Map<EqEff, Integer> m = new HashMap<>(); m.merge(new EqEff(1), 1, Integer::sum); }\n"
            + "  public static void x11Compute() { Map<EqEff, Integer> m = new HashMap<>(); m.compute(new EqEff(1), (k, v) -> 1); }\n"
            + "  public static void x12ArraysHash() { EqEff[] a = { new EqEff(1) }; Arrays.hashCode(a); }\n"
            + "  public static void x13ArraysEquals() { EqEff[] a = { new EqEff(1) }; EqEff[] b = { new EqEff(1) }; Arrays.equals(a, b); }\n"
            + "  public static void x14SetOf() { Set.of(new EqEff(1), new EqEff(2)); }\n"
            + "  public static void x15MapOf() { Map.of(new EqEff(1), 1, new EqEff(2), 2); }\n"
            + "  public static void x16Distinct() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.add(new EqEff(2)); l.stream().distinct().count(); }\n"
            + "  public static void x17ToSet() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.add(new EqEff(2)); l.stream().collect(Collectors.toSet()); }\n"
            + "  public static void x18GroupingBy() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.stream().collect(Collectors.groupingBy(e -> e)); }\n"
            + "  public static void x19Hashtable() { Hashtable<EqEff, Integer> m = new Hashtable<>(); m.put(new EqEff(1), 1); }\n"
            + "  public static void x20ConcurrentMapIface() { ConcurrentMap<EqEff, Integer> m = new ConcurrentHashMap<>(); m.put(new EqEff(1), 1); }\n"
            + "  public static void x21ChmComputeIfAbsent() { ConcurrentHashMap<EqEff, Integer> m = new ConcurrentHashMap<>(); m.computeIfAbsent(new EqEff(1), k -> 1); }\n"
            + "  public static void x22ContainsValue() { Map<Integer, EqEff> m = new HashMap<>(); m.put(1, new EqEff(1)); m.containsValue(new EqEff(2)); }\n"
            + "  public static void x23Deque() { Deque<EqEff> d = new ArrayDeque<>(); d.add(new EqEff(1)); d.contains(new EqEff(1)); }\n"
            + "  public static void x24Frequency() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); Collections.frequency(l, new EqEff(1)); }\n"
            + "  public static void x25ListOfContains() { List<EqEff> l = List.of(new EqEff(1)); l.contains(new EqEff(1)); }\n"
            + "  public static void x26CowList() { List<EqEff> l = new CopyOnWriteArrayList<>(); l.add(new EqEff(1)); l.contains(new EqEff(1)); }\n"
            + "  public static void x27MapEntryHash() { Map.entry(new EqEff(1), 1).hashCode(); }\n"
            + "  public static void x28SetCopyOf() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.add(new EqEff(2)); Set.copyOf(l); }\n"
            + "  public static void x29Vector() { Vector<EqEff> v = new Vector<>(); v.add(new EqEff(1)); v.contains(new EqEff(1)); }\n"
            + "  public static void x30MapReplace() { Map<EqEff, Integer> m = new HashMap<>(); m.replace(new EqEff(1), 1); }\n"
            + "  public static void x31OptionalEquals() { Optional.of(new EqEff(1)).equals(Optional.of(new EqEff(1))); }\n"
            + "  public static void x32ListEquals() { List<EqEff> a = new ArrayList<>(); a.add(new EqEff(1)); List<EqEff> b = new ArrayList<>(); b.add(new EqEff(1)); a.equals(b); }\n"
            + "  public static void x33LinkedHashSetCopy() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.add(new EqEff(2)); new LinkedHashSet<>(l); }\n"
            + "  public static void x34ArraysAsListContains() { Arrays.asList(new EqEff(1)).contains(new EqEff(1)); }\n"
            + "  public static void x35WeakHashMap() { Map<EqEff, Integer> m = new WeakHashMap<>(); m.put(new EqEff(1), 1); }\n"
            + "  public static void x36RemoveIf() { Map<EqEff, Integer> m = new HashMap<>(); m.remove(new EqEff(1), 1); }\n"
            + "  public static void x37ReplaceNonEmpty() { Map<Object, Integer> m = new HashMap<>(); m.put(\"a\", 1); m.replace(new EqEff(1), 1); }\n"
            + "  // ---- controls (real = 0): a pure exact element, a JDK element, or a site that runs nothing on the effectful one\n"
            + "  public static void kx01ObjectsHashPure() { Objects.hash(new EqPure(1), \"s\"); }\n"
            + "  public static void kx02SetOfPure() { Set.of(new EqPure(1), new EqPure(2), new EqPure(3)); }\n"
            + "  public static void kx03DistinctPure() { List<EqPure> l = new ArrayList<>(); l.add(new EqPure(1)); l.stream().distinct().count(); }\n"
            + "  public static void kx04GroupingByStringKey() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.stream().collect(Collectors.groupingBy(e -> \"k\" + e.v)); }\n"
            + "  public static void kx05ToList() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.stream().collect(Collectors.toList()); }\n"
            + "  public static void kx06ArraysHashStr() { String[] a = { \"a\" }; Arrays.hashCode(a); }\n"
            + "  public static void kx07ComputeStrKey() { Map<String, EqEff> m = new HashMap<>(); m.computeIfAbsent(\"a\", k -> new EqEff(1)); }\n"
            + "  public static void kx08VectorAdd() { Vector<EqEff> v = new Vector<>(); v.add(new EqEff(1)); }\n"
            + "  public static void kx09FrequencyStr() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); Collections.frequency(l, \"x\"); }\n"
            + "  public static void kx10DequeAdd() { Deque<EqEff> d = new ArrayDeque<>(); d.add(new EqEff(1)); d.peek(); }\n"
            + "  public static void kx11ContainsValueStr() { Map<EqEff, String> m = new HashMap<>(); m.put(null, \"v\"); m.containsValue(\"x\"); }\n"
            + "  public static void kx12SetOfOne() { Set.of(new EqEff(1)); }\n"
            + "  public static void kx13MapOfOne() { Map.of(new EqEff(1), 1); }\n"
            + "  public static void kx14HashtableStrKey() { Hashtable<String, EqEff> m = new Hashtable<>(); m.put(\"k\", new EqEff(1)); }\n"
            + "  public static void kx15ToMapStrKey() { List<EqEff> l = new ArrayList<>(); l.add(new EqEff(1)); l.stream().collect(Collectors.toMap(e -> \"k\" + e.v, e -> e)); }\n"
            + "}\n";

    /** Silent on 0.40.12 (executed: each wrote the file), charged now. */
    static final List<String> NEWLY = List.of("x06ObjectsHash", "x07ObjectsEquals", "x08ObjectsHashCode", "x09ComputeIfAbsent", "x10Merge", "x11Compute", "x12ArraysHash", "x13ArraysEquals", "x14SetOf", "x15MapOf", "x16Distinct", "x17ToSet", "x18GroupingBy", "x19Hashtable", "x20ConcurrentMapIface", "x21ChmComputeIfAbsent", "x22ContainsValue", "x23Deque", "x24Frequency", "x28SetCopyOf", "x29Vector", "x37ReplaceNonEmpty");
    /** Already charged on 0.40.12: must stay charged. */
    static final List<String> ALREADY = List.of("x01MapPut", "x02SetAdd", "x03ListHash", "x04HashSetCopy", "x05Contains", "x25ListOfContains", "x26CowList", "x31OptionalEquals", "x32ListEquals", "x33LinkedHashSetCopy", "x34ArraysAsListContains", "x35WeakHashMap", "x36RemoveIf");
    /** Executed: nothing written. A pure exact element, a JDK element, or a site that runs nothing on the effectful one. */
    static final List<String> CONTROLS = List.of("kx01ObjectsHashPure", "kx02SetOfPure", "kx03DistinctPure", "kx04GroupingByStringKey", "kx05ToList", "kx06ArraysHashStr", "kx07ComputeStrKey", "kx08VectorAdd", "kx09FrequencyStr", "kx10DequeAdd", "kx11ContainsValueStr", "kx12SetOfOne", "kx13MapOfOne", "kx14HashtableStrKey", "kx15ToMapStrKey");

    @Test
    void everyExecutedSiteIsCharged() throws Exception {
        Map<String, Map<String, Object>> r = scan();
        for (String fn : NEWLY) assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " runs EqEff (executed); got " + r.get("app.N." + fn));
        for (String fn : ALREADY) assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " got " + r.get("app.N." + fn));
    }

    @Test
    void controlsStayClean() throws Exception {
        Map<String, Map<String, Object>> r = scan();
        for (String fn : CONTROLS) assertTrue(inferred(r, "app.N." + fn).isEmpty(), fn + " runs no effectful body (executed); got " + r.get("app.N." + fn));
    }

    /** GENUINE-MAY, as R1166's {@code mapGetEmpty}: {@code replace} hashes its key whenever the map has a table, so a
     *  site cannot tell the empty map from a filled one; charged. STATED RESIDUAL (SOUNDNESS R1204, open): {@code Map.entry(k, v).hashCode()}
     *  (the entry's own hash over its key) is not modelled. */
    @Test
    void theMayAndTheResidualAreStated() throws Exception {
        Map<String, Map<String, Object>> r = scan();
        assertTrue(inferred(r, "app.N.x30MapReplace").contains("Fs"), "got " + r.get("app.N.x30MapReplace"));
        assertTrue(inferred(r, "app.N.x27MapEntryHash").isEmpty(), "if this now reports, close the residual in its row (R1204): " + r.get("app.N.x27MapEntryHash"));
    }

    static Map<String, Map<String, Object>> scan() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Sink.java", SINK);
        m.put("app/T.java", TYPES);
        m.put("app/N.java", MAIN);
        return scanSources(m);
    }

    static Map<String, Map<String, Object>> scanSources(Map<String, String> m) throws Exception {
        Path cls = TestCompiler.compile(m, "-g");
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Path out = cls.getParent().resolve("r.json");
            ReportWriter.writeJson(Candor.runScan(cls), out.toString());
            return byFn(out);
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }

    @SuppressWarnings("unchecked")
    static List<String> inferred(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        return row == null ? List.of() : (List<String>) row.get("inferred");
    }

    @SuppressWarnings("unchecked")
    static Map<String, Map<String, Object>> byFn(Path report) throws Exception {
        Map<String, Object> doc = new Gson().fromJson(Files.readString(report), Map.class);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Object o : (List<Object>) doc.getOrDefault("functions", new ArrayList<>())) {
            Map<String, Object> e = (Map<String, Object>) o;
            out.put((String) e.get("fn"), e);
        }
        return out;
    }
}
