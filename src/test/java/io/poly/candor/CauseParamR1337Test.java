package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1337 — a JDK Throwable constructor's cause that is the body's own PARAMETER, declared by an open JDK type
 * ({@code CliEx(Throwable c) { super(c); }}), is decided by what each CALLER passes, not by CHA over every project
 * throwable. One variable between the two arms: the cause's type. Executed on JDK 21 (scratchpad fx1337):
 * {@code viaProject(new MsgEx())} wrote the file; {@code viaForeign(new java.text.ParseException("x", 0))} wrote nothing.
 */
class CauseParamR1337Test {

    static final String SRC = ""
            + "package q;\n"
            + "class W { static void hit() { try { java.nio.file.Files.writeString(java.nio.file.Path.of(\"/nonexistent-r1337/x\"), \"x\"); } catch (Exception e) {} } }\n"
            + "class MsgEx extends RuntimeException { @Override public String getMessage() { W.hit(); return \"m\"; } }\n"
            + "class CliEx extends Exception { CliEx(Throwable c) { super(c); } }\n"
            + "class Two extends Exception { Two(Throwable c) { this(c, 1); } Two(Throwable c, int k) { super(c); } }\n"
            + "public class Use {\n"
            + "  public static Exception viaProject(MsgEx e) { return new CliEx(e); }\n"
            + "  public static Exception viaProjectNew() { return new CliEx(new MsgEx()); }\n"
            + "  public static Exception viaProjectTwoHops(MsgEx e) { return new Two(e); }\n"
            + "  public static Exception viaForeign(java.text.ParseException e) { return new CliEx(e); }\n"
            + "  public static Exception viaForeignTwoHops(java.text.ParseException e) { return new Two(e); }\n"
            + "}\n";

    /** Written FIRST: the project cause must still be charged after the change, at every hop. */
    @Test
    void aProjectCauseHandedThroughAThrowableParameterIsStillCharged() throws Exception {
        Path cls = TestCompiler.compile(Map.of("q/Use.java", SRC));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : List.of("viaProject", "viaProjectNew", "viaProjectTwoHops"))
                assertTrue(inf.getOrDefault("q.Use." + w, EffectSet.empty()).contains(Effect.FS),
                        "R1337 must not lose the project cause: " + w + " — got " + inf.get("q.Use." + w));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }

    @Test
    void aForeignCauseHandedThroughAThrowableParameterIsNotChargedAProjectGetMessage() throws Exception {
        Path cls = TestCompiler.compile(Map.of("q/Use.java", SRC));
        try {
            Map<String, EffectSet> inf = Candor.runScan(cls);
            for (String w : List.of("viaForeign", "viaForeignTwoHops"))
                assertFalse(inf.getOrDefault("q.Use." + w, EffectSet.empty()).contains(Effect.FS),
                        "R1337: a foreign cause runs no project getMessage: " + w + " — got " + inf.get("q.Use." + w));
        } finally {
            TestCompiler.rm(cls.getParent());
        }
    }
}
