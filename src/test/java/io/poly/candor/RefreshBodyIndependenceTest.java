package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/** THE ONE ASSUMPTION THE REFRESH CACHE RESTS ON, MEASURED RATHER THAN DOCUMENTED.
 *
 *  <p>{@link Refresh} keys a class's cached delta on that class's own content hash plus a whole-program
 *  digest. The digest covers every class's STRUCTURE — supertypes, access, every method and field
 *  name/descriptor/access, annotations — and the whole-program pre-pass outputs explicitly. What it does
 *  NOT cover is other classes' instruction BODIES. So the cache is sound exactly if analysing class A
 *  never reads class B's instructions: if it did, editing B's body would leave A's cached delta stale
 *  while the digest held perfectly still, and a stale delta read as current is a silent under-report.
 *
 *  <p>Writing that down as a comment would make it look considered, which is what stops a thing being
 *  measured. So this measures it. For every class in a real target, the delta is computed twice — once
 *  against the true program, once against a program whose OTHER classes have had every instruction
 *  stripped — and the two must be identical. A dependency on another body shows up immediately as a
 *  differing delta, naming the class.
 *
 *  <p>The pre-pass outputs are deliberately computed from the REAL bodies in both arms
 *  ({@code suppressibleStreamFields} is derived from bodies), because those are already in the digest.
 *  Isolating the question that way is the point: this asks only whether {@code analyze} itself reaches
 *  into another class's code.
 *
 *  <p>It drives {@link Candor#prepareScan} rather than rebuilding the pipeline, because a replica would
 *  drift from the engine and do so silently — in the one test whose entire job is to be trusted about
 *  staleness.
 */
class RefreshBodyIndependenceTest {

    @Test
    void analysisOfAClassNeverReadsAnotherClassesBody() throws Exception {
        Path target = Path.of("build/classes/java/main");
        if (!java.nio.file.Files.isDirectory(target)) target = Path.of("build/classes/java/test");
        assertTrue(java.nio.file.Files.isDirectory(target), "no compiled classes to measure against");

        Map<String, String> real = deltasAgainstRealProgram(target);
        Map<String, String> stripped = deltasAgainstStrippedProgram(target);

        assertTrue(real.size() > 50, "too few classes to be worth calling a measurement: " + real.size());
        assertEquals(real.keySet(), stripped.keySet(), "the two arms analysed different classes");

        List<String> differing = new ArrayList<>();
        for (var e : real.entrySet())
            if (!e.getValue().equals(stripped.get(e.getKey()))) differing.add(e.getKey());

        assertTrue(differing.isEmpty(),
                "analysing these classes CHANGED when other classes' bodies were stripped, so their\n"
                + "cached deltas can go stale while the whole-program digest holds still — the refresh\n"
                + "cache is unsound for them and the digest must cover more than structure:\n  "
                + String.join("\n  ", differing.subList(0, Math.min(10, differing.size()))));

        // THE CONTROL. The comparison above is vacuous unless stripping is capable of changing an
        // answer at all — if the strip were a no-op, or the deltas were empty, every class would agree
        // trivially and this test would pass while measuring nothing.
        long nonEmpty = real.values().stream().filter(v -> v.length() > 2).count();
        assertTrue(nonEmpty > 20, "only " + nonEmpty + " classes produced a non-empty delta; the "
                + "agreement above would be trivial");
    }

    private Map<String, String> deltasAgainstRealProgram(Path target) throws Exception {
        List<ClassNode> classes = Candor.prepareScan(target, null, false);
        return deltas(classes, ctx(), null);
    }

    private Map<String, String> deltasAgainstStrippedProgram(Path target) throws Exception {
        List<ClassNode> classes = Candor.prepareScan(target, null, false);
        AnalysisContext master = ctx();
        // Structure-only twins, built AFTER the pre-passes have read the real bodies.
        List<ClassNode> bodyless = new ArrayList<>();
        for (ClassNode cn : classes) bodyless.add(strip(cn));
        return deltas(classes, master, bodyless);
    }

    /** Analyse each class into its own overlay and return the encoded delta per class. When
     *  {@code bodyless} is given, the whole program visible to {@code analyze} is the stripped one
     *  EXCEPT for the class currently under analysis, which is its real self. */
    private Map<String, String> deltas(List<ClassNode> classes, AnalysisContext master, List<ClassNode> bodyless) {
        if (bodyless != null) {
            master.ALL = new ArrayList<>(bodyless);
            master.byName.clear();
            for (ClassNode s : bodyless) master.byName.put(s.name, s);
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < classes.size(); i++) {
            ClassNode cn = classes.get(i);
            if (bodyless != null) {           // swap the real class in for its own analysis
                master.byName.put(cn.name, cn);
                master.ALL.set(i, cn);
            }
            try {
                AnalysisContext overlay = new AnalysisContext(master);
                AnalysisState.install(overlay);
                try { Candor.analyze(cn); } finally { AnalysisState.install(master); }
                out.put(cn.name, Refresh.Delta.encode(overlay).toString());
                overlay.mergeInto(master);
            } catch (Throwable t) {
                out.put(cn.name, "THREW:" + t.getClass().getName());
            }
            if (bodyless != null) {           // put the stripped twin back
                master.byName.put(cn.name, bodyless.get(i));
                master.ALL.set(i, bodyless.get(i));
            }
        }
        return out;
    }

    /** A structural twin: same everything, no code. Try/catch ranges and local-variable tables are
     *  dropped too — they reference labels that only exist inside the instruction list, so leaving them
     *  behind would make the twin malformed and the arms would differ for a reason that has nothing to
     *  do with the question being asked. */
    private static ClassNode strip(ClassNode cn) {
        ClassNode copy = new ClassNode();
        cn.accept(copy);
        for (MethodNode m : copy.methods) {
            m.instructions.clear();
            if (m.tryCatchBlocks != null) m.tryCatchBlocks.clear();
            if (m.localVariables != null) m.localVariables.clear();
        }
        return copy;
    }
}
