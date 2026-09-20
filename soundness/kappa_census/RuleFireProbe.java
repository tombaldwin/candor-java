package io.poly.candor;

import io.poly.candor.model.Effect;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * SOUNDNESS R508/R509 — <b>the "does the rule still fire?" probe.</b>
 *
 * <p>Reads a jar, enumerates every method whose OWNER falls under a {@code Rules.KAPPA_COVERED_PREFIXES}
 * entry, and asks {@link Classifier#classify} about each one. It reports how many MATCHED.
 *
 * <p>Why this exists, and what it is NOT. R508 is the structural limit: a κ rule is keyed on
 * owner+method and cannot express <i>"this owner forks in ≤1.2 and not in ≥1.3"</i>. R509 is what that
 * cost: R493's Exposed rules were written as {@code owner.equals("org.jetbrains.exposed.sql.QueriesKt")}
 * against 0.52.0, Exposed 1.0.0 moved the library to {@code org.jetbrains.exposed.v1.jdbc.QueriesKt},
 * every owner-equals missed, the block fell through to {@code return null} — and {@code org.jetbrains}
 * is κ-COVERED, so that null is a certified purity claim, not a disclosure. Measured: a complete data
 * layer reported {@code 0 functions reach effects} with {@code coverage: null}, {@code invisible: null},
 * and {@code deny Db} exiting 0.
 *
 * <p><b>The cheap signal is that the match count against the CURRENT jar goes to zero.</b> That is the
 * whole instrument. It does NOT re-census N versions per prefix — the R508 sweep argued against that
 * (an exhaustive enumeration times N, answering a question no single user has). It asks one question of
 * one jar: are these rules still pointed at code that exists?
 *
 * <p>It reads {@code Rules.KAPPA_COVERED_PREFIXES} rather than spelling a second copy — the same
 * ask-the-authority rule that {@link KappaQuery}'s {@code specName()} header records, because a second
 * copy of a table is how the two names diverged in R496.
 *
 * <p><b>Scope is deliberately the COVERED prefixes and no further.</b> For a NON-covered prefix
 * (testcontainers, net.bramp, commons-exec, zt-exec, im4java) a package rename floors the call to
 * {@code invisible} and is DISCLOSED — loud, not silent. Coverage is the only place where a rename is a
 * cardinal sin, so coverage is the only place the download cost is justified.
 *
 * <p>Output is TSV on stdout, one block per jar:
 * <pre>
 *   JAR    &lt;file&gt;   &lt;coveredMembers&gt;  &lt;matched&gt;  &lt;distinctMatchedOwners&gt;
 *   OWNER  &lt;file&gt;   &lt;owner&gt;           &lt;matched&gt;  &lt;effects,…&gt;
 * </pre>
 * The caller decides what a zero means; this harness only counts. Usage:
 * {@code java -cp <probe-dir>:<candor-all.jar> io.poly.candor.RuleFireProbe [--owners] <jar|dir>…}
 */
public final class RuleFireProbe {

    public static void main(String[] args) throws Exception {
        boolean owners = false;
        List<Path> jars = new ArrayList<>();
        for (String a : args) {
            if (a.equals("--owners")) { owners = true; continue; }
            Path p = Path.of(a);
            if (Files.isDirectory(p)) {
                try (var s = Files.list(p)) {
                    s.filter(f -> f.toString().endsWith(".jar")).sorted().forEach(jars::add);
                }
            } else {
                jars.add(p);
            }
        }
        PrintWriter w = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
        for (Path jar : jars) probe(jar, owners, w);
        w.flush();
    }

    private static void probe(Path jar, boolean printOwners, PrintWriter w) {
        // owner -> matched count; owner -> effect names
        Map<String, int[]> byOwner = new TreeMap<>();
        Map<String, TreeSet<String>> effByOwner = new TreeMap<>();
        int[] covered = {0};
        int[] matched = {0};
        try (ZipFile zf = new ZipFile(jar.toFile())) {
            var en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String n = e.getName();
                if (!n.endsWith(".class")) continue;
                // A multi-release jar's versioned copies carry the SAME owner name; counting them twice
                // would inflate the match count but cannot turn a zero into a non-zero, and skipping them
                // could hide a member that exists only on a newer JDK. Keep them.
                byte[] b;
                try (InputStream in = zf.getInputStream(e)) { b = in.readAllBytes(); }
                ClassReader cr;
                try { cr = new ClassReader(b); } catch (Throwable t) { continue; }
                String internal = cr.getClassName();
                int slash = internal.lastIndexOf('/');
                if (slash <= 0) continue;                   // default package: no namespace to key on
                // Ask the AUTHORITY. `Candor.kappaCovers` is the same predicate the engine uses to decide
                // whether a floored call is ledgered, and it takes the PACKAGE, not the owner — spelling a
                // second copy here is how R496's two spellings of the effect table diverged.
                if (!Candor.kappaCovers(internal.substring(0, slash).replace('/', '.'))) continue;
                String ownerDotted = internal.replace('/', '.');
                cr.accept(new ClassVisitor(Opcodes.ASM9) {
                    @Override public MethodVisitor visitMethod(int acc, String name, String desc,
                                                               String sig, String[] ex) {
                        covered[0]++;
                        Effect eff;
                        try { eff = Classifier.classify(ownerDotted, name, desc); }
                        catch (Throwable t) { return null; }
                        if (eff != null) {
                            matched[0]++;
                            byOwner.computeIfAbsent(ownerDotted, k -> new int[1])[0]++;
                            effByOwner.computeIfAbsent(ownerDotted, k -> new TreeSet<>())
                                      .add(eff.specName());
                        }
                        return null;
                    }
                }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            }
        } catch (IOException io) {
            w.println("ERR\t" + jar.getFileName() + "\t" + io);
            return;
        }
        w.println("JAR\t" + jar.getFileName() + "\t" + covered[0] + "\t" + matched[0]
                + "\t" + byOwner.size());
        if (printOwners) {
            for (Map.Entry<String, int[]> e : byOwner.entrySet()) {
                w.println("OWNER\t" + jar.getFileName() + "\t" + e.getKey() + "\t" + e.getValue()[0]
                        + "\t" + String.join(",", effByOwner.get(e.getKey())));
            }
        }
    }

    private RuleFireProbe() {}
}
