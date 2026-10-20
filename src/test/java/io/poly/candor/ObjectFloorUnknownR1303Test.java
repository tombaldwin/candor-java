package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1303 — THE OBJECT FLOOR STANDS IN FOR EDGES, SO IT MUST CARRY AN OVERRIDE'S {@code Unknown}. {@code H.toString}
 * runs {@code ref.toString()} on a field declared {@code E} — javac names {@code java/lang/Object} as the owner because the
 * abstract {@code E} declares no toString — and {@code E} has 14 subtypes, past the CHA bound, so the site is decided by the
 * S4 floor. One subtype's toString ({@code EU}) writes a file through reflection: the engine can only say {@code Unknown}
 * for it, and the floor counted concrete effects alone, so {@code H.toString} read PURE (executed on JDK 21: javaagent-c
 * fx/r1303, {@code new H(new EU()).toString()} wrote the file). Before R1299 the site CHA'd over {@code Object} and an
 * UNRELATED class's effectful toString ({@code Other}) disclosed it — for the wrong reason. The control {@code H2} has the
 * same shape over a hierarchy whose every toString is a constant: it stays pure.
 */
class ObjectFloorUnknownR1303Test {

    static Map<String, String> sources() {
        Map<String, String> m = new HashMap<>();
        m.put("p/W.java", "package p;\npublic class W { public static void hit(String s) { try { java.nio.file.Files.writeString("
                + "java.nio.file.Path.of(\"/nonexistent-r1303/\" + s), s); } catch (Exception e) {} } }\n");
        m.put("p/E.java", "package p;\npublic abstract class E { public abstract int k(); }\n");
        m.put("p/E2.java", "package p;\npublic abstract class E2 { public abstract int k(); }\n");
        for (int i = 0; i <= 12; i++) {
            m.put("p/Ea" + i + ".java", "package p;\npublic class Ea" + i + " extends E { public int k() { return " + i
                    + "; } @Override public String toString() { return \"Ea" + i + "\"; } }\n");
            m.put("p/Eb" + i + ".java", "package p;\npublic class Eb" + i + " extends E2 { public int k() { return " + i
                    + "; } @Override public String toString() { return \"Eb" + i + "\"; } }\n");
        }
        m.put("p/EU.java", "package p;\npublic class EU extends E { public int k() { return 99; } @Override public String toString() {"
                + " try { Class.forName(System.getProperty(\"r1303.cls\", \"p.W\")).getMethod(\"hit\", String.class).invoke(null, \"eu\"); }"
                + " catch (Exception e) { throw new RuntimeException(e); } return \"EU\"; } }\n");
        m.put("p/EbP.java", "package p;\npublic class EbP extends E2 { public int k() { return 98; } @Override public String toString() { return \"EbP\"; } }\n");
        m.put("p/Other.java", "package p;\npublic class Other { @Override public String toString() { W.hit(\"other\"); return \"Other\"; } }\n");
        m.put("p/H.java", "package p;\npublic class H { final E ref; public H(E r) { ref = r; } @Override public String toString() { return \"H(\" + ref.toString() + \")\"; } }\n");
        m.put("p/H2.java", "package p;\npublic class H2 { final E2 ref; public H2(E2 r) { ref = r; } @Override public String toString() { return \"H2(\" + ref.toString() + \")\"; } }\n");
        return m;
    }

    @Test
    void anOverridesUnknownReachesTheCallerPastTheBound() throws Exception {
        Path cls = TestCompiler.compile(sources());
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            assertTrue(inf.getOrDefault("p.EU.toString", EffectSet.empty()).contains(Effect.UNKNOWN),
                    "precondition: the reflective override is Unknown — got " + inf.get("p.EU.toString"));
            EffectSet h = inf.getOrDefault("p.H.toString", EffectSet.empty());
            assertTrue(h.contains(Effect.UNKNOWN), "R1303: H.toString may run EU.toString — got " + h);
            EffectSet h2 = inf.getOrDefault("p.H2.toString", EffectSet.empty());
            assertFalse(h2.contains(Effect.UNKNOWN) || h2.contains(Effect.FS),
                    "R1299 control: every E2 toString is a constant, and Other is not an E2 — got " + h2);
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }
}
