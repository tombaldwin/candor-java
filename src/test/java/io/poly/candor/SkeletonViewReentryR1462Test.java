package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1462 — a JDK skeleton member that RETURNS an object built over {@code this} (AbstractList's iterator,
 * listIterator, subList, spliterator; AbstractMap's keySet/values) runs the project's overrides later, when that object
 * is used: {@code for (s : list)} over a project {@code AbstractList} whose {@code get} writes a file. The site table had
 * no line for those members (the acquiring body itself runs no user code), so the iterating function read pure; and the
 * argument contract resolved a re-entry SET to its first member only ({@code it.hasNext()} runs {@code size()}, not the
 * first hook {@code get}).
 *
 * <p>Executed on JDK 21 (scratchpad javaagent-r1462/fx/shapes, ground-truth-shapes.txt): every positive below wrote its
 * file; {@code ctlNew} and {@code ctlParam} (an exact {@code ArrayList}) did not. No project {@code Iterator} exists in
 * the tree, so none of this rests on R1461's bounded fan-out at {@code Iterator.next}.
 */
class SkeletonViewReentryR1462Test {

    static final String HIT = "static void hit() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1462/x\"), \"x\"); } catch (Exception e) { } }";

    static Map<String, String> src() {
        Map<String, String> m = new HashMap<>();
        m.put("sv/S.java", "package sv;\nclass S { " + HIT + " }\n");
        m.put("sv/GetList.java", "package sv;\npublic class GetList extends java.util.AbstractList<String> {\n"
                + " public String get(int i) { S.hit(); return \"x\"; } public int size() { return 1; } }\n");
        m.put("sv/SizeList.java", "package sv;\npublic class SizeList extends java.util.AbstractList<String> {\n"
                + " public String get(int i) { return \"x\"; } public int size() { S.hit(); return 1; } }\n");
        m.put("sv/RmList.java", "package sv;\npublic class RmList extends java.util.AbstractList<String> {\n"
                + " public String get(int i) { return \"x\"; } public int size() { return 1; }\n"
                + " public String remove(int i) { S.hit(); return \"x\"; } }\n");
        m.put("sv/EsMap.java", "package sv;\npublic class EsMap extends java.util.AbstractMap<String, String> {\n"
                + " public java.util.Set<java.util.Map.Entry<String, String>> entrySet() { S.hit(); return new java.util.HashMap<String, String>().entrySet(); } }\n");
        m.put("sv/Use.java", "package sv;\nimport java.util.*;\npublic class Use {\n"
                // the iterating function's receiver is project-typed or a provable `new`: the function itself is charged
                + " public static int projParam(GetList l) { int n = 0; for (String s : l) n++; return n; }\n"
                + " public static int local() { List<String> l = new GetList(); int n = 0; for (String s : l) n++; return n; }\n"
                + " public static String sub(GetList l) { return l.subList(0, 1).iterator().next(); }\n"
                // a JDK-typed parameter: the argument contract charges the CALLER that passes the project list
                + " static int foreach(List<String> l) { int n = 0; for (String s : l) n++; return n; }\n"
                + " static boolean hasNext(List<String> l) { return l.iterator().hasNext(); }\n"
                + " static void itRemove(List<String> l) { Iterator<String> it = l.iterator(); it.next(); it.remove(); }\n"
                + " static int keys(Map<String, String> m) { int n = 0; for (String k : m.keySet()) n++; return n; }\n"
                + " public static void cForeach() { foreach(new GetList()); }\n"
                + " public static void cHasNext() { hasNext(new SizeList()); }\n"
                + " public static void cRemove() { itRemove(new RmList()); }\n"
                + " public static void cKeys() { keys(new EsMap()); }\n"
                // controls: an exact JDK list runs none of the project overrides
                + " public static int ctlNew() { int n = 0; for (String s : new ArrayList<>(List.of(\"a\"))) n++; return n; }\n"
                + " public static void ctlParam() { foreach(new ArrayList<>(List.of(\"a\"))); }\n"
                + "}\n");
        return m;
    }

    @Test
    void aSkeletonViewRunsTheProjectOverridesItWasBuiltOver() throws Exception {
        Path cls = TestCompiler.compile(new HashMap<>(src()));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String fn : List.of("projParam", "local", "sub", "cForeach", "cHasNext", "cRemove", "cKeys"))
                assertTrue(inf.getOrDefault("sv.Use." + fn, EffectSet.empty()).contains(Effect.FS),
                        "executed: sv.Use." + fn + " wrote the file through a JDK skeleton's view — got " + inf.get("sv.Use." + fn));
            for (String fn : List.of("ctlNew", "ctlParam"))
                assertFalse(inf.getOrDefault("sv.Use." + fn, EffectSet.empty()).contains(Effect.FS),
                        "executed: sv.Use." + fn + " iterates an exact ArrayList and wrote nothing — got " + inf.get("sv.Use." + fn));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    @Test
    void theTableNamesTheViewHooks() {
        assertTrue(JdkSites.hookNames("java/util/AbstractList", "iterator", "()Ljava/util/Iterator;").containsAll(List.of("get", "size", "remove")));
        assertTrue(JdkSites.hookNames("java/util/AbstractList", "listIterator", "(I)Ljava/util/ListIterator;").containsAll(List.of("get", "set", "add", "remove")));
        assertTrue(JdkSites.hookNames("java/util/AbstractMap", "keySet", "()Ljava/util/Set;").contains("entrySet"));
        assertTrue(JdkSites.hookNames("java/util/AbstractMap", "values", "()Ljava/util/Collection;").contains("entrySet"));
        // a package-private or final JDK member is not a hook a user override can answer
        assertFalse(JdkSites.hookNames("java/util/HashMap", "entrySet", "()Ljava/util/Set;").contains("getNode"));
    }
}
