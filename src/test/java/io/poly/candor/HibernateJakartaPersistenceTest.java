package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Hibernate-6 / Jakarta Data persistence → Db (the effect-leaf rules), plus the soundness fix for the
 * repository default-method Db fabrication. Classify-level tests pin the leaves; the integration tests
 * drive a full scan and assert generated CRUD gets Db while a pure `default` helper does NOT (and an
 * effectful default keeps its real effect).
 *
 * <p>Provenance: κ batch 24, 2026-06-21.
 */
class HibernateJakartaPersistenceTest {

    // ── classify-level: the new Hibernate-6 leaves ───────────────────────────────────────────────────

    /** Hibernate 6 StatelessSession CRUD terminals each issue their own SQL → Db; the query/criteria
     *  FACTORIES are pure builders (their execution is on the returned query). */
    @Test
    void hibernate6StatelessSessionTerminalsAreDb() {
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.StatelessSession", "insert", "(Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.StatelessSession", "update", "(Ljava/lang/Object;)V"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.StatelessSession", "upsert", "(Ljava/lang/Object;)V"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.StatelessSession", "delete", "(Ljava/lang/Object;)V"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.StatelessSession", "get", "(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.StatelessSession", "getIdentifier", "(Ljava/lang/Object;)Ljava/lang/Object;"));
        // builders must stay pure — classifying them Db would fabricate on a query-construction call
        assertNull(Classifier.classify("org.hibernate.StatelessSession", "getCriteriaBuilder", "()Ljakarta/persistence/criteria/HibernateCriteriaBuilder;"));
        assertNull(Classifier.classify("org.hibernate.StatelessSession", "createSelectionQuery", "(Ljava/lang/String;Ljava/lang/Class;)Lorg/hibernate/query/SelectionQuery;"));
        assertNull(Classifier.classify("org.hibernate.StatelessSession", "createMutationQuery", "(Ljava/lang/String;)Lorg/hibernate/query/MutationQuery;"));
    }

    /** Hibernate 6 SelectionQuery / MutationQuery — only the TERMINAL result/execute verbs round-trip; the
     *  setX builders stay pure. */
    @Test
    void hibernate6SplitQueryTerminalsAreDb() {
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.query.SelectionQuery", "getResultList", "()Ljava/util/List;"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.query.SelectionQuery", "getSingleResult", "()Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.query.SelectionQuery", "getResultCount", "()J"));
        assertEquals(Effect.DB, Classifier.classify("org.hibernate.query.MutationQuery", "executeUpdate", "()I"));
        assertNull(Classifier.classify("org.hibernate.query.SelectionQuery", "setMaxResults", "(I)Lorg/hibernate/query/SelectionQuery;"));
        assertNull(Classifier.classify("org.hibernate.query.MutationQuery", "setParameter", "(Ljava/lang/String;Ljava/lang/Object;)Lorg/hibernate/query/MutationQuery;"));
    }

    /** A direct call on a Jakarta Data repository BASE interface hits the datastore → Db; the jakarta.data
     *  VALUE types (Sort/Order/…) and the Object protocol stay pure. */
    @Test
    void jakartaDataBaseInterfaceIsDb() {
        assertEquals(Effect.DB, Classifier.classify("jakarta.data.repository.CrudRepository", "save", "(Ljava/lang/Object;)Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("jakarta.data.repository.BasicRepository", "deleteById", "(Ljava/lang/Object;)V"));
        assertEquals(Effect.DB, Classifier.classify("jakarta.data.repository.CrudRepository", "findAll", "(Ljakarta/data/Order;)Ljava/util/stream/Stream;"));
        // a value type under jakarta.data.* that does NOT end in "Repository" is pure query construction
        assertNull(Classifier.classify("jakarta.data.Sort", "asc", "(Ljava/lang/String;)Ljakarta/data/Sort;"));
        // Object protocol on a repository stays pure
        assertNull(Classifier.classify("jakarta.data.repository.CrudRepository", "toString", "()Ljava/lang/String;"));
    }

    // ── integration: Jakarta Data project repository + the default-method fabrication fix ────────────

    /** A project interface extending a Jakarta Data base is promoted into repoTypes, so its GENERATED CRUD
     *  calls infer Db — BUT a pure `default` method on it must NOT fabricate Db (the soundness fix), and an
     *  effectful default must keep its real effect (the fix must not drop it). */
    @Test
    void jakartaDataRepoCrudIsDb_defaultMethodsResolveToTheirBody() throws Exception {
        Path cls = compile(Map.of(
            "jakarta/data/repository/CrudRepository.java",
            "package jakarta.data.repository; public interface CrudRepository<T,K> { <S extends T> S save(S e); void deleteById(K id); }",
            "app/FruitRepository.java", String.join("\n",
                "package app;",
                "import jakarta.data.repository.CrudRepository;",
                "public interface FruitRepository extends CrudRepository<String,Integer> {",
                "  default String greet() { return \"hi\"; }",
                "  default void leak() throws Exception { new java.io.FileInputStream(\"x\").read(); } }"),
            "app/Use.java", String.join("\n",
                "package app;",
                "public class Use {",
                "  public static void crud(FruitRepository r){ r.save(\"a\"); }",
                "  public static String pure(FruitRepository r){ return r.greet(); }",
                "  public static void eff(FruitRepository r) throws Exception { r.leak(); } }")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Use.crud").toNames().contains("Db"),
                "generated CRUD save() on a Jakarta Data repo must be Db, got " + r.get("app.Use.crud"));
            assertTrue(eff(r, "app.Use.pure").isEmpty(),
                "a PURE default helper must not fabricate Db, got " + r.get("app.Use.pure"));
            EffectSet e = eff(r, "app.Use.eff");
            assertTrue(e.toNames().contains("Fs"),
                "an EFFECTFUL default must keep its real effect (Fs), got " + e);
            assertFalse(e.toNames().contains("Db"),
                "an effectful default must not also fabricate Db, got " + e);
        } finally { rm(cls.getParent()); }
    }

    // ── harness (mirrors the Round*FixesTest pattern) ───────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

}
