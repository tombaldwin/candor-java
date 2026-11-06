package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.ReasonClass;
import io.poly.candor.model.UnknownReason;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1461 — a CHA edge from a JDK generic type to a project implementor whose type argument is PROVABLY
 * incompatible with the receiver's declared one becomes a disclosed {@code Unknown[dispatch:…]} on the same site
 * (a hedge, never a drop). The {@link GenericHedge} reader is a new instrument, so it is calibrated in all three
 * directions: an incompatible pair it must demote, a compatible pair it must keep, and unresolvable receivers (raw,
 * wildcard, type variable, Object, a CHECKCAST) it must keep.
 *
 * <p>Executed on JDK 21 (scratchpad javaagent-r1461/fx, the field-fp item-1 shapes): {@code for (Integer x :
 * Collection<Integer>)} over real JDK collections never runs {@code SpanIter.next}; under heap pollution — a raw
 * {@code iterator()} override (H1) or an unchecked {@code (Collection)} upcast (H2) — it does, and writes the file. So
 * the edge cannot be dropped, and the row must say {@code Unknown}.
 */
class GenericHedgeR1461Test {

    static final String HIT = "static void hit() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1461/x\"), \"x\"); } catch (Exception e) { } }";

    static Map<String, String> src() {
        Map<String, String> m = new HashMap<>();
        m.put("gh/E.java", "package gh;\nclass E { " + HIT + " static void env() { System.getenv(\"R1461\"); } }\n");
        m.put("gh/Span.java", "package gh;\npublic final class Span { }\n");
        m.put("gh/SpanIter.java", "package gh;\npublic class SpanIter implements java.util.Iterator<Span> {\n"
                + " public boolean hasNext() { return false; } public Span next() { E.hit(); return new Span(); } }\n");
        m.put("gh/IntIter.java", "package gh;\npublic class IntIter implements java.util.Iterator<Integer> {\n"
                + " public boolean hasNext() { return false; } public Integer next() { E.env(); return 1; } }\n");
        // H1: a raw override — a List<Integer> whose iterator is the Span iterator
        m.put("gh/RawBag.java", "package gh;\n@SuppressWarnings({\"unchecked\",\"rawtypes\"})\n"
                + "public class RawBag extends java.util.ArrayList<Integer> { public java.util.Iterator iterator() { return new SpanIter(); } }\n");
        m.put("gh/Use.java", "package gh;\nimport java.util.*;\n@SuppressWarnings({\"unchecked\",\"rawtypes\"})\npublic class Use {\n"
                + " List<Integer> f;\n"
                + " static List<Integer> make() { return new ArrayList<>(); }\n"
                // INCOMPATIBLE — must demote SpanIter.next and keep IntIter.next
                + " public static int param(Collection<Integer> c) { int n = 0; for (Integer x : c) n++; return n; }\n"
                + " public static int paramObj(Collection<Integer> c) { int n = 0; for (Object x : c) n++; return n; }\n"
                + " public int field() { int n = 0; for (Integer x : f) n++; return n; }\n"
                + " public static int call() { int n = 0; for (Integer x : make()) n++; return n; }\n"
                + " public static int local() { List<Integer> l = make(); int n = 0; Iterator<Integer> it = l.iterator(); while (it.hasNext()) { it.next(); n++; } return n; }\n"
                + " public static int jdkCall(Map<String, Integer> m) { int n = 0; for (Integer x : m.values()) n++; return n; }\n"
                // COMPATIBLE — must keep SpanIter.next
                + " public static int spans(Iterable<Span> c) { int n = 0; for (Span x : c) n++; return n; }\n"
                // UNRESOLVABLE — must keep SpanIter.next
                + " public static int raw(Collection c) { int n = 0; for (Object x : c) n++; return n; }\n"
                + " public static int wild(Collection<? extends Number> c) { int n = 0; for (Object x : c) n++; return n; }\n"
                + " public static <T> int tvar(Collection<T> c) { int n = 0; for (Object x : c) n++; return n; }\n"
                + " public static int obj(Collection<Object> c) { int n = 0; for (Object x : c) n++; return n; }\n"
                + " public static int cast(Object o) { int n = 0; for (Object x : (Collection<Integer>) o) n++; return n; }\n"
                + " public static int merged(boolean b, Collection<Integer> c, Collection d) { int n = 0; for (Object x : (b ? c : d)) n++; return n; }\n"
                // a declared local over that merge: its LocalVariableTypeTable (-g) is the declaration javac checked
                // every use against, so it decides; without -g the producers decide, and the raw one keeps the edge
                + " public static int mergedLocal(boolean b, Collection<Integer> c, Collection d) { Collection<Integer> e = b ? c : d; int n = 0; for (Object x : e) n++; return n; }\n"
                // H1 / H2: the executed polluted callers — the row of each iterating function must carry the Unknown
                + " public static void h1() { param(new RawBag()); }\n"
                + " public static void h2(List<Span> s) { param((Collection) s); }\n"
                + "}\n");
        return m;
    }

    static final String SPAN = "gh.SpanIter.next", INT = "gh.IntIter.next", WHY = "dispatch:java.util.Iterator.next";

    @Test
    void anIncompatibleImplementorIsDemotedToADisclosedDispatchAndEveryOtherKeepsItsEdge() throws Exception {
        for (String[] flags : List.of(new String[0], new String[] {"-g"})) {
            Path cls = TestCompiler.compile(new HashMap<>(src()), flags);
            try {
                Map<String, EffectSet> inf = Candor.runScan(cls);
                AnalysisContext c = AnalysisState.ctx();
                String arm = flags.length == 0 ? "no -g" : "-g";
                for (String fn : List.of("param", "paramObj", "field", "call", "local", "jdkCall")) {
                    String id = "gh.Use." + fn;
                    Set<String> e = c.edges.getOrDefault(id, Set.of());
                    assertFalse(e.contains(SPAN), arm + ": " + id + " — an Iterator<Integer> receiver must not edge Iterator<Span>.next, got " + e);
                    assertTrue(e.contains(INT), arm + ": " + id + " — the compatible Iterator<Integer>.next keeps its edge, got " + e);
                    assertTrue(c.unknownWhy.getOrDefault(id, new TreeSet<>()).stream().anyMatch(w -> w.toString().equals(WHY)),
                            arm + ": " + id + " — the demoted edge is DISCLOSED on the same site, got " + c.unknownWhy.get(id));
                    assertFalse(c.unknownWhy.getOrDefault(id, new TreeSet<>()).stream().anyMatch(w -> w.toString().equals("dispatch:java.util.Iterator.hasNext")),
                            arm + ": " + id + " — SpanIter.hasNext is pure, so its demotion is not disclosed, got " + c.unknownWhy.get(id));
                    assertTrue(inf.get(id).contains(Effect.UNKNOWN) && inf.get(id).contains(Effect.ENV) && !inf.get(id).contains(Effect.FS),
                            arm + ": " + id + " — Unknown for the demoted SpanIter's Fs, Env from the compatible IntIter — got " + inf.get(id));
                }
                // COMPATIBLE: an Iterable<Span> keeps SpanIter.next — and demotes IntIter.next, the mirror pair
                Set<String> sp = c.edges.getOrDefault("gh.Use.spans", Set.of());
                assertTrue(sp.contains(SPAN) && !sp.contains(INT), arm + ": gh.Use.spans — Iterator<Span> keeps SpanIter, demotes IntIter, got " + sp);
                for (String fn : List.of("raw", "wild", "tvar", "obj", "cast", "merged")) {
                    String id = "gh.Use." + fn;
                    Set<String> e = c.edges.getOrDefault(id, Set.of());
                    assertTrue(e.contains(SPAN) && e.contains(INT), arm + ": " + id + " — unresolvable: today's edges are kept, got " + e);
                    assertFalse(c.unknownWhy.getOrDefault(id, new TreeSet<>()).stream().anyMatch(w -> w.toString().equals(WHY)),
                            arm + ": " + id + " — nothing demoted, nothing disclosed, got " + c.unknownWhy.get(id));
                }
                Set<String> ml = c.edges.getOrDefault("gh.Use.mergedLocal", Set.of());
                assertEquals(flags.length == 0, ml.contains(SPAN), arm + ": gh.Use.mergedLocal — LVTT decides under -g, producers without, got " + ml);
                // H1/H2 callers: the polluted call reaches `param`, whose row discloses the dispatch; the gate on
                // `deny Fs Unknown` stays red and bare `deny Fs` keeps IntIter's (over-approximate) Fs here.
                for (String fn : List.of("h1", "h2"))
                    assertTrue(inf.get("gh.Use." + fn).contains(Effect.UNKNOWN), arm + ": gh.Use." + fn + " got " + inf.get("gh.Use." + fn));
            } finally {
                TestCompiler.rm(cls.getParent());
            }
        }
    }

    /** The disclosure is decided after the fixpoint: a demoted body that carries NOTHING the site lacks needs none
     *  (SpanIter.hasNext is pure), and a body whose only channel is {@code invisible} — a call into a package this scan
     *  cannot analyse — DOES, or the chained consumer would lose the one thing telling it to look. */
    @Test
    void theDisclosureIsDecidedByWhatTheDemotedBodyCarries() throws Exception {
        Path app = TestCompiler.compileApp(
                Map.of("com/obscure/lib/Widget.java", "package com.obscure.lib; public class Widget { public static void doStuff(){} }"),
                Map.of("gi/Span.java", "package gi;\npublic final class Span { }\n",
                        "gi/BlindIter.java", "package gi;\npublic class BlindIter implements java.util.Iterator<Span> {\n"
                                + " public boolean hasNext() { return false; } public Span next() { com.obscure.lib.Widget.doStuff(); return new Span(); } }\n",
                        "gi/Use.java", "package gi;\nimport java.util.*;\npublic class Use {\n"
                                + " public static int ints(Collection<Integer> c) { int n = 0; for (Integer x : c) n++; return n; }\n}\n"));
        try {
            Candor.runScan(app);
            AnalysisContext c = AnalysisState.ctx();
            TreeSet<?> why = c.unknownWhy.getOrDefault("gi.Use.ints", new TreeSet<>());
            assertTrue(why.stream().anyMatch(w -> w.toString().equals("dispatch:java.util.Iterator.next")),
                    "BlindIter.next carries only `invisible`: its demoted edge must still be disclosed, got " + why);
            assertFalse(why.stream().anyMatch(w -> w.toString().equals("dispatch:java.util.Iterator.hasNext")),
                    "BlindIter.hasNext is pure: demoting it loses nothing and discloses nothing, got " + why);
            assertFalse(c.edges.getOrDefault("gi.Use.ints", Set.of()).contains("gi.BlindIter.next"));
        } finally {
            TestCompiler.rm(app.getParent());
        }
    }

    /** A HEDGE MUST NOT DELETE A DISCLOSURE (audit of ad3d625, item a): where the demoted body's Unknown came from
     *  reflection, the site's disclosure carries that class too, so a reason-scoped {@code deny Unknown[reflect]} that
     *  failed before the hedge still fails. Measured on the candidate without this: 1 -> 0. */
    @Test
    void theDisclosureCarriesTheDemotedBodysReasonClasses() throws Exception {
        Path cls = TestCompiler.compile(new HashMap<>(Map.of(
                "gr/Span.java", "package gr;\npublic final class Span { }\n",
                "gr/SpanIter.java", "package gr;\npublic class SpanIter implements java.util.Iterator<Span> {\n"
                        + " public boolean hasNext() { return false; }\n"
                        + " public Span next() { try { Class.forName(System.nanoTime() > 0 ? \"a.B\" : \"c.D\").getDeclaredConstructor().newInstance(); } catch (Exception e) { } return new Span(); } }\n",
                "gr/Use.java", "package gr;\nimport java.util.*;\npublic class Use {\n"
                        + " public static int ints(Collection<Integer> c) { int n = 0; for (Integer x : c) n++; return n; }\n"
                        + " public static int up(Collection<Integer> c) { return ints(c); }\n}\n")));
        try {
            Candor.runScan(cls);
            AnalysisContext c = AnalysisState.ctx();
            TreeSet<UnknownReason> why = c.unknownWhy.getOrDefault("gr.Use.ints", new TreeSet<>());
            assertFalse(c.edges.getOrDefault("gr.Use.ints", Set.of()).contains("gr.SpanIter.next"), "still demoted");
            assertTrue(why.stream().anyMatch(w -> w.toString().equals("dispatch:java.util.Iterator.next")), "got " + why);
            assertTrue(why.stream().anyMatch(w -> ReasonClass.classify(w.format()).token().equals("reflect")),
                    "the demoted body's reflect class must survive on the site, got " + why);
            Map<String, TreeSet<String>> acc = Policy.scanReasonClassAcc();
            assertTrue(acc.getOrDefault("gr.Use.up", new TreeSet<>()).contains("reflect"),
                    "…and reach its callers, as it did through the edge, got " + acc.get("gr.Use.up"));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    /** THE R1462 SHAPE (audit of ad3d625, item b): a {@code List<String>} over a project {@code AbstractList<String>} whose
     *  {@code get} writes. The demoted edge is the wrong-type {@code Iterator<Integer>.next} — the classifier is RIGHT —
     *  and the real path ({@code AbstractList$Itr.next -> get}) is not edged at a JDK-typed receiver by design
     *  ({@code Cha#reentryOverOwner}); the argument contract charges the CALLER that passes the project list. So: the
     *  caller keeps {@code Fs}; the iterating function and a field-held receiver are disclosed, never silent. Executed
     *  (javaagent-r1461/fx5): {@code caller()} and {@code field()} both write. */
    @Test
    void theR1462ShapeIsDisclosedAtTheIteratorAndChargedAtTheCaller() throws Exception {
        Path cls = TestCompiler.compile(new HashMap<>(Map.of(
                "hx/E.java", "package hx;\nclass E { " + HIT + " }\n",
                "hx/Skel.java", "package hx;\npublic class Skel extends java.util.AbstractList<String> {\n"
                        + " public String get(int i) { E.hit(); return \"x\"; } public int size() { return 1; } }\n",
                "hx/IntIter.java", "package hx;\npublic class IntIter implements java.util.Iterator<Integer> {\n"
                        + " public boolean hasNext() { return false; } public Integer next() { E.hit(); return 1; } }\n",
                "hx/Use.java", "package hx;\nimport java.util.*;\npublic class Use {\n List<String> f = new Skel();\n"
                        + " public static int strs(List<String> l) { int n = 0; for (String s : l) n++; return n; }\n"
                        + " public static int caller() { return strs(new Skel()); }\n"
                        + " public int field() { int n = 0; for (String s : f) n++; return n; }\n}\n")));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            AnalysisContext c = AnalysisState.ctx();
            assertTrue(inf.get("hx.Use.caller").contains(Effect.FS), "the argument contract charges the caller: " + inf.get("hx.Use.caller"));
            for (String fn : List.of("hx.Use.strs", "hx.Use.field")) {
                assertTrue(inf.get(fn).contains(Effect.UNKNOWN), fn + " must be disclosed, got " + inf.get(fn));
                assertTrue(c.unknownWhy.getOrDefault(fn, new TreeSet<>()).stream()
                        .anyMatch(w -> w.toString().equals("dispatch:java.util.Iterator.next")), fn + " got " + c.unknownWhy.get(fn));
            }
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    /** SCOPE (Tom's ruling, 2026-11-05): the hedge covers the JDK COLLECTION owners only. A {@code Supplier<Integer>}
     *  receiver over the program's only {@code Supplier<String>} is the same argument one package over, and it keeps
     *  its edge unless the {@code CANDOR_R1461_WIDE} measurement arm is on. */
    @Test
    void aNonCollectionOwnerKeepsItsEdge() throws Exception {
        Path cls = TestCompiler.compile(new HashMap<>(Map.of(
                "gs/E.java", "package gs;\nclass E { " + HIT + " }\n",
                "gs/StrSup.java", "package gs;\npublic class StrSup implements java.util.function.Supplier<String> {\n"
                        + " public String get() { E.hit(); return \"x\"; } }\n",
                "gs/Use.java", "package gs;\npublic class Use {\n"
                        + " public static Object sup(java.util.function.Supplier<Integer> s) { return s.get(); }\n}\n")));
        try {
            Candor.runScan(cls);
            AnalysisContext c = AnalysisState.ctx();
            assertEquals(!GenericHedge.WIDE, c.edges.getOrDefault("gs.Use.sup", Set.of()).contains("gs.StrSup.get"),
                    "java.util.function is outside the ruled scope: the edge is kept by default, got " + c.edges.get("gs.Use.sup"));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    /** The signature reader itself, over JDK class files: the binding chain {@code Map<String,Integer>.values()} →
     *  {@code Collection<Integer>} → {@code Iterator<Integer>}, and a raw use binding nothing. */
    @Test
    void theSignatureReaderResolvesThroughJdkSupertypes() {
        AnalysisState.newContext();
        GenericHedge.G al = GenericHedge.G.cls("java/util/ArrayList", List.of(GenericHedge.G.cls("java/lang/Integer", List.of())));
        GenericHedge.G asColl = GenericHedge.asSuper(al, "java/util/Collection");
        assertNotNull(asColl);
        assertEquals("java/lang/Integer", asColl.args().get(0).name());
        GenericHedge.G rawAl = GenericHedge.G.cls("java/util/ArrayList", List.of());
        assertEquals('U', GenericHedge.asSuper(rawAl, "java/lang/Iterable").args().get(0).kind());
        assertTrue(GenericHedge.disjoint("java/lang/Integer", "java/lang/String"));
        assertFalse(GenericHedge.disjoint("java/lang/Integer", "java/lang/Number"));
        assertFalse(GenericHedge.disjoint("java/lang/Integer", "java/lang/Object"));
        GenericHedge.MethodSig ms = GenericHedge.parseMethod("<T::Ljava/lang/Comparable<-TT;>;>(Ljava/util/Map<TK;+Ljava/util/List<[I>;>;)Ljava/util/Iterator<TE;>;");
        assertEquals(List.of("T"), ms.typeParams());
        assertEquals("java/util/Iterator", ms.ret().name());
        assertNull(GenericHedge.info("com/example/NotOnThisClasspath"));
    }
}
