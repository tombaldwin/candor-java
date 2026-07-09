package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The general "subclass a classify-MODELED external effectful type, call an inherited method" fix: the
 * call-site owner is the project subclass (no classify rule) and the real body is in the external base
 * (unscanned), so the inherited effect read silent-pure. candor now re-classifies against the external
 * supertype the JVM dispatches to. (Generalizes the Testcontainers GenericContainer-subclass find;
 * complementary to the persistence registries, which cover bases classify does NOT model.)
 */
class InheritedModeledBaseTest {

    /** A project class extends a modeled external effectful type (java.io.FileInputStream) and calls an
     *  inherited method — the inherited Fs must be attributed (was silent-pure). */
    @Test
    void subclassOfModeledStreamInheritsItsEffect() throws Exception {
        Path cls = compile(Map.of(
            "app/MyStream.java",
            "package app;\n"
                + "class MyStream extends java.io.FileInputStream { MyStream() throws Exception { super(\"x\"); } }",
            "app/Use.java",
            "package app;\n"
                + "public class Use {\n"
                + "  public static int rd(MyStream s) throws Exception { return s.read(); }\n" // inherited read → Fs
                + "  public static long sk(MyStream s) throws Exception { return s.skip(1); } }")); // inherited skip → Fs
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Use.rd").contains(Effect.FS),
                "an inherited read() from FileInputStream must be Fs, got " + r.get("app.Use.rd"));
            assertTrue(eff(r, "app.MyStream.<init>").contains(Effect.FS),
                "the super(\"x\") ctor opens the file → Fs, got " + r.get("app.MyStream.<init>"));
        } finally { rm(cls.getParent()); }
    }

    /** No fabrication: a project class extends a NON-effectful external type (java.util.ArrayList); an
     *  inherited add() has no classify rule, so it must stay pure. */
    @Test
    void subclassOfPureBaseStaysPure() throws Exception {
        Path cls = compile(Map.of(
            "app/MyList.java", "package app; class MyList extends java.util.ArrayList<String> {}",
            "app/Use.java",
            "package app; public class Use { public static void add(MyList l){ l.add(\"x\"); l.size(); } }"));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Use.add").isEmpty(),
                "inherited ArrayList methods have no effect rule — must stay pure (no fabrication), got " + r.get("app.Use.add"));
        } finally { rm(cls.getParent()); }
    }

    /** Testcontainers leaf: start AND execInContainer shell out → Exec. */
    @Test
    void testcontainersExecVerbsAreExec() {
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.GenericContainer", "start", "()V"));
        assertEquals(Effect.EXEC, Classifier.classify("org.testcontainers.containers.GenericContainer", "execInContainer", "([Ljava/lang/String;)Lorg/testcontainers/containers/Container$ExecResult;"));
    }

    // ── harness ─────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

}
