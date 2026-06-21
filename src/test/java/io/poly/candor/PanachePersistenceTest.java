package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * κ batch 25 — Quarkus Panache persistence → Db. Panache (active-record `Fruit.listAll()`/`f.persist()` and
 * the `PanacheRepository` alternative) is the dominant Quarkus persistence, and it read SILENT-PURE: the
 * call-site owner is the PROJECT entity/repo and the real body lives in Panache (unscanned), so candor's gate
 * was blind to all DB access in a Panache app. These tests pin that the three patterns now infer Db while a
 * lookalike non-Panache class stays pure (no fabrication). Panache must be EXTERNAL (compiled to the classpath
 * but NOT scanned) to reproduce the gap — hence the two-phase compile.
 */
class PanachePersistenceTest {

    @Test
    void panacheActiveRecordAndRepositoryInferDb_lookalikeStaysPure() throws Exception {
        Path app = compileApp(
            // ── external Panache base types (on the classpath, NOT scanned — like the real dependency) ──
            Map.of(
                "io/quarkus/hibernate/orm/panache/PanacheEntityBase.java",
                "package io.quarkus.hibernate.orm.panache;\n"
                    + "public class PanacheEntityBase {\n"
                    + "  public void persist() {}\n"
                    + "  public void delete() {}\n"
                    + "  public static java.util.List listAll() { return null; }\n"
                    + "  public static Object findById(Object id) { return null; }\n"
                    + "  public static long count() { return 0; } }",
                "io/quarkus/hibernate/orm/panache/PanacheRepositoryBase.java",
                "package io.quarkus.hibernate.orm.panache;\n"
                    + "public interface PanacheRepositoryBase<E, I> {\n"
                    + "  default void persist(E e) {}\n"
                    + "  default java.util.List<E> listAll() { return null; } }"),
            // ── the project (scanned) ──
            Map.of(
                "app/Fruit.java",
                "package app; import io.quarkus.hibernate.orm.panache.PanacheEntityBase;\n"
                    + "public class Fruit extends PanacheEntityBase { public String name; }",
                "app/FruitRepo.java",
                "package app; import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;\n"
                    + "public interface FruitRepo extends PanacheRepositoryBase<Fruit, Long> {}",
                "app/Plain.java",
                "package app;\n"
                    + "public class Plain { public void persist() {} public static long count() { return 0; } }",
                "app/Svc.java",
                "package app;\n"
                    + "public class Svc {\n"
                    + "  public static void save(Fruit f) { f.persist(); }\n"          // active-record instance
                    + "  public static java.util.List all() { return Fruit.listAll(); }\n" // active-record static finder
                    + "  public static void viaRepo(FruitRepo r, Fruit f) { r.persist(f); }\n" // repository
                    + "  public static void plain(Plain p) { p.persist(); Plain.count(); } }")); // lookalike → pure
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.Svc.save").contains(Effect.DB),
                "Panache active-record persist() must be Db, got " + r.get("app.Svc.save"));
            assertTrue(eff(r, "app.Svc.all").contains(Effect.DB),
                "Panache static finder listAll() must be Db, got " + r.get("app.Svc.all"));
            assertTrue(eff(r, "app.Svc.viaRepo").contains(Effect.DB),
                "Panache repository persist() must be Db, got " + r.get("app.Svc.viaRepo"));
            assertTrue(eff(r, "app.Svc.plain").isEmpty(),
                "a non-Panache class with persist()/count() must stay pure (no fabrication), got " + r.get("app.Svc.plain"));
        } finally { rm(app.getParent()); }
    }

    /** PanacheQuery terminals are Db; its builders (page/range/withLock) stay pure. */
    @Test
    void panacheQueryTerminalsAreDb() {
        assertEquals(Effect.DB, Classifier.classify("io.quarkus.hibernate.orm.panache.PanacheQuery", "list", "()Ljava/util/List;"));
        assertEquals(Effect.DB, Classifier.classify("io.quarkus.hibernate.orm.panache.PanacheQuery", "firstResult", "()Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("io.quarkus.hibernate.orm.panache.PanacheQuery", "count", "()J"));
        assertEquals(null, Classifier.classify("io.quarkus.hibernate.orm.panache.PanacheQuery", "page", "(II)Lio/quarkus/hibernate/orm/panache/PanacheQuery;"));
    }

    // ── two-phase harness: lib → classpath (not scanned), app → scanned ─────────────────────────────

    private static Path compileApp(Map<String, String> lib, Map<String, String> app) throws Exception {
        javax.tools.JavaCompiler jc = javax.tools.ToolProvider.getSystemJavaCompiler();
        Assumptions.assumeTrue(jc != null, "no system Java compiler (JRE-only) — skip");
        Path base = Files.createTempDirectory("candor-panache");
        Path libOut = compileTo(jc, base.resolve("src-lib"), lib, base.resolve("lib"), null);
        compileTo(jc, base.resolve("src-app"), app, base.resolve("app"), libOut);
        return base.resolve("app");
    }

    private static Path compileTo(javax.tools.JavaCompiler jc, Path src, Map<String, String> sources,
            Path out, Path classpath) throws Exception {
        List<String> files = new ArrayList<>();
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path p = src.resolve(e.getKey());
            Files.createDirectories(p.getParent());
            Files.writeString(p, e.getValue());
            files.add(p.toString());
        }
        Files.createDirectories(out);
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        if (classpath != null) { args.add("-cp"); args.add(classpath.toString()); }
        args.addAll(files);
        assertEquals(0, jc.run(null, null, null, args.toArray(new String[0])), "javac");
        return out;
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    private static void rm(Path dir) throws Exception {
        if (dir == null || !Files.exists(dir)) return;
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> { try { Files.delete(p); } catch (Exception ignored) {} });
        }
    }
}
