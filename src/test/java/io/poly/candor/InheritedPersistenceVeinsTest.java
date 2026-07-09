package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * κ batch 26 — the "inherited into a project type" silent-pure vein class (the generalization of the Panache
 * find). A persistence verb inherited from an UNMODELED external base, called via a PROJECT subtype, read
 * silent-pure (the call owner is the project class, so neither classify nor repoTypes fired). Four frameworks
 * confirmed by a dogfood probe: Micronaut Data (repository), Ebean + ActiveJDBC (active-record), jOOQ DAOImpl
 * (DAO base). Each base is EXTERNAL (compiled to the classpath, NOT scanned) to reproduce the gap.
 */
class InheritedPersistenceVeinsTest {

    @Test
    void inheritedPersistenceFromAnExternalBaseInfersDb_lookalikeStaysPure() throws Exception {
        Path app = compileApp(
            Map.of(
                "io/micronaut/data/repository/CrudRepository.java",
                "package io.micronaut.data.repository;\n"
                    + "public interface CrudRepository<E,ID> { <S extends E> S save(S e); java.util.Optional<E> findById(ID id); }",
                "io/ebean/Model.java",
                "package io.ebean; public class Model { public void save(){} public boolean delete(){return true;} }",
                "org/javalite/activejdbc/Model.java",
                "package org.javalite.activejdbc;\n"
                    + "public class Model { public boolean saveIt(){return true;} public static java.util.List findAll(){return null;} }",
                "org/jooq/impl/DAOImpl.java",
                "package org.jooq.impl;\n"
                    + "public abstract class DAOImpl<R,P,T> { public void insert(P o){} public P findById(T id){return null;} }"),
            Map.of(
                "app/Models.java", String.join("\n",
                    "package app;",
                    "class Book {}",
                    "interface BookRepo extends io.micronaut.data.repository.CrudRepository<Book,Long> {}",
                    "class Customer extends io.ebean.Model {}",
                    "class Person extends org.javalite.activejdbc.Model {}",
                    "class BookDao extends org.jooq.impl.DAOImpl<Object,Book,Long> {}",
                    "class Plain { void save(){} static java.util.List findAll(){return null;} }"), // lookalike → pure
                "app/Use.java", String.join("\n",
                    "package app;",
                    "public class Use {",
                    "  static Object mnSave(BookRepo r, Book b){ return r.save(b); }",       // Micronaut Data
                    "  static Object mnFind(BookRepo r){ return r.findById(1L); }",
                    "  static void ebeanSave(Customer c){ c.save(); }",                       // Ebean active-record
                    "  static boolean ebeanDel(Customer c){ return c.delete(); }",
                    "  static boolean ajdbcSave(Person p){ return p.saveIt(); }",             // ActiveJDBC active-record
                    "  static Object ajdbcAll(){ return Person.findAll(); }",                 // (static finder)
                    "  static void jooqIns(BookDao d, Book b){ d.insert(b); }",               // jOOQ DAO
                    "  static Object jooqFind(BookDao d){ return d.findById(1L); }",
                    "  static void plainSave(Plain p){ p.save(); }",                          // lookalike → pure
                    "  static Object plainAll(){ return Plain.findAll(); } }")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : List.of("mnSave", "mnFind", "ebeanSave", "ebeanDel",
                    "ajdbcSave", "ajdbcAll", "jooqIns", "jooqFind")) {
                assertTrue(eff(r, "app.Use." + m).contains(Effect.DB),
                    m + " must infer Db (inherited persistence verb), got " + r.get("app.Use." + m));
            }
            assertTrue(eff(r, "app.Use.plainSave").isEmpty(),
                "a lookalike non-framework save() must stay pure, got " + r.get("app.Use.plainSave"));
            assertTrue(eff(r, "app.Use.plainAll").isEmpty(),
                "a lookalike non-framework findAll() must stay pure, got " + r.get("app.Use.plainAll"));
        } finally { rm(app.getParent()); }
    }

    // ── two-phase harness: lib → classpath (not scanned), app → scanned ─────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

}
