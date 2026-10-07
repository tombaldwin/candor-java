package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SECOND SPELLINGS OF A CALL THE κ LEDGER OR THE CLASSIFIER ALREADY ANSWERS. Every pair below is one
 * operation written two ways, and in every pair the second spelling read SILENT — no effect, no
 * {@code invisible} — on the pre-fix build. EXECUTED on compiled consumers in the lane's fixtures (the inherited
 * and method-reference spellings wrote their files; the struts forward reached {@code RequestDispatcher.forward};
 * displaytag's lookup read its bundle; the redis facade invoked {@code ReactiveValueOperations.set} and
 * {@code findByIdOrNull} invoked {@code CrudRepository.findById}). Stub owners carry the real names and
 * descriptors ({@code javap} of the real jars and of a kotlinc-compiled consumer); bodies are irrelevant here.
 */
class KappaSecondSpellingTest {

    private static Set<String> blind(String fn) {
        return AnalysisState.ctx().blindDirect.getOrDefault(fn, new TreeSet<>());
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** An inherited external member reached through a project subclass compiles with the PROJECT owner, so the
     *  ledger skipped it; the direct spelling on the external owner was always ledgered. */
    @Test
    void anInheritedExternalMemberIsLedgeredLikeItsDirectSpelling() throws Exception {
        Path app = compileApp(Map.of(
                "com/acme/Base.java", "package com.acme; public class Base { public void save(String p) {} }",
                "org/mark/Marker.java", "package org.mark; public interface Marker {}"),
            Map.of("app/Sub.java", String.join("\n",
                "package app;",
                "public class Sub extends com.acme.Base {",
                "  void viaInherited() { save(\"x\"); }",
                "  void viaOwnBody() { mine(); }",
                "  void mine() {}",
                "}"),
                "app/Direct.java", "package app; public class Direct { void viaDirect() { new com.acme.Base().save(\"x\"); } }",
                // a JDK-backed project class carrying an UNCOVERED marker interface: the inherited body is
                // ArrayList's (loadable, declares size()) and Object's (hashCode) — the marker must not be named
                "app/L.java", "package app; public class L extends java.util.ArrayList<String> implements org.mark.Marker {"
                    + " int n() { return size(); } int h() { return hashCode(); } }"));
        try {
            Candor.runScan(app);
            assertTrue(blind("app.Direct.viaDirect").contains("com.acme"), "control: the direct spelling is ledgered");
            assertTrue(blind("app.Sub.viaInherited").contains("com.acme"),
                    "an inherited external member reached through a project subclass must be ledgered too");
            assertFalse(blind("app.Sub.viaOwnBody").contains("com.acme"), "a call to the project's OWN body ledgers nothing");
            assertFalse(blind("app.L.n").contains("org.mark"), "ArrayList declares size(): the marker is not a candidate");
            assertFalse(blind("app.L.h").contains("org.mark"), "Object declares hashCode(): the marker is not a candidate");
        } finally { rm(app.getParent()); }
    }

    /** SOUNDNESS R929: a method reference to an unclassified member of an uncovered package is ledgered exactly
     *  as the call spelling is; a reference to a COVERED pure member stays unledgered. */
    @Test
    void aMethodReferenceIsLedgeredLikeItsCallSpelling() throws Exception {
        Path app = compileApp(Map.of(
                "com/mongodb/client/MongoClient.java",
                "package com.mongodb.client; public interface MongoClient { Object getDatabase(String n); }"),
            Map.of("app/Q.java", String.join("\n",
                "package app; import java.util.*;",
                "public class Q {",
                "  void call(com.mongodb.client.MongoClient mc, List<String> ns) { for (String n : ns) mc.getDatabase(n); }",
                "  void ref(com.mongodb.client.MongoClient mc, List<String> ns) { ns.forEach(mc::getDatabase); }",
                "  void pureRef(List<String> ns) { ns.stream().map(String::trim).count(); }",
                "}")));
        try {
            Candor.runScan(app);
            assertTrue(blind("app.Q.call").contains("com.mongodb.client"), "control: the call spelling is ledgered");
            assertTrue(blind("app.Q.ref").contains("com.mongodb.client"), "the reference spelling must be ledgered too");
            assertTrue(blind("app.Q.pureRef").isEmpty(), "a covered JDK reference ledgers nothing");
        } finally { rm(app.getParent()); }
    }

    /** Kotlin facades: kotlinc emits `ReactiveValueOperationsExtensionsKt.setAndAwait(ops, …)` and
     *  `CrudRepositoryExtensionsKt.findByIdOrNull(repo, id)` — non-inline extensions over a receiver the
     *  classifier already charges. The pure builder facade beside them stays pure. */
    @Test
    void kotlinExtensionFacadesCarryTheirReceiversCharge() throws Exception {
        Path app = compileApp(Map.of(
                "org/springframework/data/redis/core/ReactiveValueOperations.java",
                "package org.springframework.data.redis.core; public interface ReactiveValueOperations<K, V> { Object set(K k, V v); }",
                "org/springframework/data/redis/core/ReactiveValueOperationsExtensionsKt.java",
                "package org.springframework.data.redis.core; public final class ReactiveValueOperationsExtensionsKt {"
                    + " public static Object setAndAwait(ReactiveValueOperations o, Object k, Object v, Object cont) { return null; } }",
                "org/springframework/data/redis/core/RedisScriptExtensionsKt.java",
                "package org.springframework.data.redis.core; public final class RedisScriptExtensionsKt {"
                    + " public static Object RedisScript(String s) { return null; } }",
                "org/springframework/data/repository/CrudRepository.java",
                "package org.springframework.data.repository; public interface CrudRepository<T, ID> { java.util.Optional<T> findById(ID id); }",
                "org/springframework/data/repository/CrudRepositoryExtensionsKt.java",
                "package org.springframework.data.repository; public final class CrudRepositoryExtensionsKt {"
                    + " public static Object findByIdOrNull(CrudRepository r, Object id) { return null; } }"),
            Map.of("app/K.java", String.join("\n",
                "package app;",
                "import org.springframework.data.redis.core.*; import org.springframework.data.repository.*;",
                "public class K {",
                "  Object facade(ReactiveValueOperations<String, String> o) { return ReactiveValueOperationsExtensionsKt.setAndAwait(o, \"k\", \"v\", null); }",
                "  Object direct(ReactiveValueOperations<String, String> o) { return o.set(\"k\", \"v\"); }",
                "  Object script() { return RedisScriptExtensionsKt.RedisScript(\"return 1\"); }",
                "  Object repoFacade(CrudRepository<Object, Long> r) { return CrudRepositoryExtensionsKt.findByIdOrNull(r, 1L); }",
                "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "app.K.direct").contains(Effect.DB), "control: the receiver spelling is Db");
            assertTrue(eff(r, "app.K.facade").contains(Effect.DB), "the Kotlin facade is the same Redis call");
            assertTrue(eff(r, "app.K.repoFacade").contains(Effect.DB), "findByIdOrNull is findById");
            assertTrue(eff(r, "app.K.script").isEmpty(), "a pure builder facade over no receiver stays pure");
        } finally { rm(app.getParent()); }
    }

    /** SOUNDNESS R727: struts' request pipeline, reached as the protected hooks a project subclass calls, and
     *  displaytag's bundle lookup. The member the pipeline does NOT charge stays pure. */
    @Test
    void strutsPipelineAndDisplaytagLookupAreCharged() throws Exception {
        String rp = "package org.apache.struts.action; public class RequestProcessor {"
                + " protected void doForward(String u, Object rq, Object rs) {} protected void doInclude(String u, Object rq, Object rs) {}"
                + " public void process(Object rq, Object rs) {} protected void log(String m) {} }";
        Path app = compileApp(Map.of(
                "org/apache/struts/action/RequestProcessor.java", rp,
                "org/apache/struts/tiles/TilesRequestProcessor.java",
                "package org.apache.struts.tiles; public class TilesRequestProcessor extends org.apache.struts.action.RequestProcessor {}",
                "org/displaytag/Messages.java",
                "package org.displaytag; public final class Messages { public static String getString(String k) { return k; } }"),
            Map.of("app/Fwd.java", String.join("\n",
                "package app;",
                "public class Fwd extends org.apache.struts.action.RequestProcessor {",
                "  void fwd() { doForward(\"/x\", null, null); }",
                "  void inc() { doInclude(\"/x\", null, null); }",
                "  void quiet() { log(\"x\"); }",
                "}"),
                "app/Tiles.java", "package app; public class Tiles extends org.apache.struts.tiles.TilesRequestProcessor {"
                    + " void fwd() { doForward(\"/x\", null, null); } }",
                "app/D.java", "package app; public class D {"
                    + " void run(org.apache.struts.action.RequestProcessor p) { p.process(null, null); }"
                    + " String msg() { return org.displaytag.Messages.getString(\"k\"); } }"));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String fn : new String[] {"app.Fwd.fwd", "app.Fwd.inc", "app.Tiles.fwd", "app.D.run"})
                assertTrue(eff(r, fn).contains(Effect.NET), fn + " forwards/includes/sends — must read Net, got " + eff(r, fn));
            assertTrue(eff(r, "app.D.msg").contains(Effect.FS), "Messages.getString loads its bundle — Fs");
            assertTrue(eff(r, "app.Fwd.quiet").isEmpty(), "log() is not on the pipeline list — stays pure");
        } finally { rm(app.getParent()); }
    }
}
