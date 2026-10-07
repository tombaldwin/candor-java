package io.poly.candor;

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
}
