package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.ReasonClass;
import io.poly.candor.model.UnknownReason;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R675 (row R712) — <b>the §4 reason KIND of every {@code Unknown} the classifier returns, one
 * row per rule, derived from the rule's own shape.</b>
 *
 * <p>{@code effectMetadata} tagged all 38 of them with the constant {@code Kind.REFLECT}. §6.2's reason
 * CLASS is the closed vocabulary {@code deny E Unknown[class…]} quantifies over, so the label is not
 * cosmetic: the java.io filter/buffered DELEGATION — whose own rule comment says it *"DELEGATES to a
 * wrapped stream of unknown concrete type … which candor cannot resolve"*, i.e. a {@code dispatch} —
 * was filed under {@code reflect}, and {@code deny Unknown[dispatch,unresolved]} (the form the engine's
 * own parse-time lint steers users toward) therefore could not see 918 holes across the census.
 * {@code com.sun.jna.Function.invoke} was filed under {@code reflect} and is {@code native}.
 *
 * <p><b>THE DERIVATION, because a table of 38 hand-assigned labels is worth nothing without the rule that
 * assigned them.</b> §4 states what the kinds are FOR: *"Lets a consumer tell irreducible opacity
 * (reflection, native) from the IMPROVABLE kind ({@code dispatch:}/{@code callback:} — a missing impl or
 * an unresolved higher-order target, often resolved by widening the analysed inputs)."* Applied to these
 * rules that is a two-question decision, and the answers are read off each rule's own comment rather than
 * off its owner's package name:
 * <ol>
 *   <li>does the call cross into MACHINE CODE (an intrinsic, a JNI/Panama/FFI boundary)? → {@code native};</li>
 *   <li>else did an OWNER TYPE get formed with a NAMED member whose concrete implementation this scan
 *       did not see? → {@code dispatch}. (The test is the shape of the hole, not our odds of closing it:
 *       candor-spec's VALUE-PROVENANCE Phase 2 was stopped on {@code FilterInputStream#in} precisely
 *       because it is JDK-inherited and not resolvable by a field-origin summary.)</li>
 *   <li>else the target is chosen at runtime from data or metadata and no widening of the inputs can
 *       recover it — {@code eval}, an EL/script string, core reflection, a class loader, an instrumentation
 *       rewrite, or a deserializer reflectively rebuilding an attacker-chosen object graph → {@code reflect},
 *       which is also the class candor-ts gives {@code eval()} ({@code reflect:eval}), so the family agrees
 *       on the question rather than only on the word.</li>
 * </ol>
 * No FOURTH class is minted: {@code callback}/{@code indirect} needs a function-VALUE (java's callback
 * holes are tagged elsewhere, at the lambda/handle sites) and {@code ambiguous} cannot arise in a bytecode
 * model, where an invoke always carries owner+name+descriptor. SOUNDNESS R681 records the SPEC already
 * missing a clause for shipped behaviour, so inventing a class here would be the expensive move.
 *
 * <p><b>The two NEAR-MISSES, reported rather than hidden.</b> {@code MethodHandle.invoke*} is a call
 * through a first-class function value and would read as {@code callback} on the letter of §4; it stays
 * {@code reflect} because the handle is nearly always obtained from a {@code Lookup}, which is core
 * reflection, and a user writing {@code deny Unknown[reflect]} means to catch it. The XXE-able parse rules
 * ({@code DocumentBuilder}/{@code SAXParser}/{@code XMLReader.parse}, {@code Transformer.transform}) are
 * opaque because an external entity can be resolved from the PAYLOAD — not reflection, not native, not a
 * missing impl. {@code reflect} is the closest of the five available kinds and is an approximation; the
 * alternative would be an off-vocabulary prefix projecting to {@code unresolved}, which is a SPEC question
 * and not an engine one.
 *
 * <p><b>Why an OWNER key is not a shortcut.</b> All 38 rules are owner-keyed and no owner appears in two of
 * them, and {@link Classifier#unknownKind} is consulted only once {@code classify} has already answered
 * {@code UNKNOWN} — so the method/descriptor dimension cannot change the answer, and the alternative (a
 * second copy of each rule's CONDITION) is the §G shape that has cost this repo repeatedly.
 */
class UnknownReasonKindTableTest {

    /** One row per {@code return Effect.UNKNOWN} site in {@link Classifier}: a call that PROVES the rule
     *  fires, and the kind that rule's shape licenses. */
    private record Rule(String owner, String method, String desc, UnknownReason.Kind kind, String why) {}

    private static final String OBJ = "()Ljava/lang/Object;";

    private static final List<Rule> TABLE = List.of(
        // ── irreducible: core reflection, dynamic invocation, class loading/definition ────────────────
        new Rule("java.lang.reflect.Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                UnknownReason.Kind.REFLECT, "core reflection — the target is a runtime Method value"),
        new Rule("java.lang.reflect.Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;",
                UnknownReason.Kind.REFLECT, "core reflection"),
        new Rule("java.lang.Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;",
                UnknownReason.Kind.REFLECT, "a class named by a runtime STRING; runs its <clinit>"),
        new Rule("java.lang.reflect.Proxy", "newProxyInstance", OBJ,
                UnknownReason.Kind.REFLECT, "a synthesized implementation dispatching through an InvocationHandler"),
        new Rule("java.lang.invoke.MethodHandle", "invokeExact", OBJ,
                UnknownReason.Kind.REFLECT, "java.lang.invoke IS the reflection API; see the near-miss above"),
        new Rule("java.lang.invoke.MethodHandles$Lookup", "defineClass", "([B)Ljava/lang/Class;",
                UnknownReason.Kind.REFLECT, "defines a hidden class from bytes — metaprogramming"),
        new Rule("java.lang.ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;",
                UnknownReason.Kind.REFLECT, "loads + initializes a class named at runtime"),
        new Rule("java.net.URLClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;",
                UnknownReason.Kind.REFLECT, "ditto, off caller-supplied search URLs"),
        new Rule("java.lang.instrument.Instrumentation", "redefineClasses", "()V",
                UnknownReason.Kind.REFLECT, "rewrites loaded bytecode — metaprogramming"),
        // ── irreducible: the target rides a PAYLOAD (deserialization / eval / expression languages) ───
        new Rule("java.io.ObjectInputStream", "readObject", OBJ,
                UnknownReason.Kind.REFLECT, "a deserializer reflectively rebuilds an attacker-chosen graph"),
        new Rule("java.beans.XMLDecoder", "readObject", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("org.yaml.snakeyaml.Yaml", "load", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("org.apache.commons.lang3.SerializationUtils", "deserialize", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("com.thoughtworks.xstream.XStream", "fromXML", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("com.esotericsoftware.kryo.Kryo", "readObject", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("com.caucho.hessian.io.HessianInput", "readObject", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("javax.script.ScriptEngine", "eval", OBJ,
                UnknownReason.Kind.REFLECT, "runs a code string — the canonical reflect: shape (cf. candor-ts eval)"),
        new Rule("javax.el.ValueExpression", "getValue", OBJ,
                UnknownReason.Kind.REFLECT, "an EL string resolves members reflectively"),
        new Rule("jakarta.el.ValueExpression", "getValue", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("org.springframework.expression.Expression", "getValue", OBJ,
                UnknownReason.Kind.REFLECT, "SpEL — ditto"),
        new Rule("org.mvel2.MVEL", "eval", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("org.apache.commons.jexl3.JexlExpression", "evaluate", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("ognl.Ognl", "getValue", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("org.jruby.embed.ScriptingContainer", "runScriptlet", OBJ,
                UnknownReason.Kind.REFLECT, "runs a script string"),
        new Rule("org.python.util.PythonInterpreter", "exec", "(Ljava/lang/String;)V",
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("bsh.Interpreter", "eval", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("clojure.lang.Compiler", "eval", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("groovy.util.Eval", "me", OBJ,
                UnknownReason.Kind.REFLECT, "ditto"),
        new Rule("groovy.lang.MetaClass", "invokeMethod", OBJ,
                UnknownReason.Kind.REFLECT, "the metaclass registry resolves the target — the rule's comment "
                + "says \"Groovy dynamic dispatch IS reflection … exactly like Method.invoke\""),
        new Rule("javax.tools.JavaCompiler", "run", "()I",
                UnknownReason.Kind.REFLECT, "compiles, and runs annotation processors found by ServiceLoader"),
        new Rule("org.aopalliance.intercept.MethodInvocation", "proceed", OBJ,
                UnknownReason.Kind.REFLECT, "the interceptor chain invokes the intercepted target reflectively; "
                + "widening the scanned inputs reaches method.invoke, not an impl"),
        new Rule("javax.xml.parsers.DocumentBuilder", "parse", OBJ,
                UnknownReason.Kind.REFLECT, "XXE — the effect rides the payload; an approximation, see above"),
        new Rule("javax.xml.transform.Transformer", "transform", "()V",
                UnknownReason.Kind.REFLECT, "ditto"),
        // ── NATIVE: the call crosses into machine code ────────────────────────────────────────────────
        new Rule("java.lang.foreign.SymbolLookup", "find", OBJ,
                UnknownReason.Kind.NATIVE, "Panama — resolves a native symbol to call"),
        new Rule("com.sun.jna.Function", "invoke", OBJ,
                UnknownReason.Kind.NATIVE, "JNA — the rule's own comment: \"a native call runs arbitrary "
                + "machine code\". Was reflect:, and R675 names it"),
        new Rule("sun.misc.Unsafe", "getLong", "(J)J",
                UnknownReason.Kind.NATIVE, "raw memory through JVM intrinsics"),
        new Rule("ai.onnxruntime.OrtSession", "run", OBJ,
                UnknownReason.Kind.NATIVE, "the rule's own comment: \"opaque native inference (can't see into native)\""),
        // ── DISPATCH: an unresolved RECEIVER, named, and improvable ────────────────────────────────────
        new Rule("java.io.FilterInputStream", "read", "()I",
                UnknownReason.Kind.DISPATCH, "the rule's own comment: \"DELEGATES to a wrapped stream of "
                + "unknown concrete type … which candor cannot resolve\". 918 census holes were filed reflect:")
    );

    /** The SECOND spelling of each multi-owner rule — the same return site reached through a sibling owner.
     *  Not extra rules: the delegation rule has eight owners and the Panama rule two, and a kind table keyed
     *  on the owner must answer for EVERY one of them or the fix covers one spelling and not its siblings,
     *  which is the defect class this whole vein is about. */
    private static final List<Rule> SIBLINGS = List.of(
        new Rule("java.io.FilterOutputStream", "write", "(I)V", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.io.BufferedOutputStream", "flush", "()V", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.io.BufferedInputStream", "read", "()I", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.io.FilterReader", "read", "()I", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.io.BufferedReader", "read", "()I", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.io.FilterWriter", "write", "(I)V", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.io.BufferedWriter", "close", "()V", UnknownReason.Kind.DISPATCH, "delegation"),
        new Rule("java.lang.foreign.Linker", "upcallStub", OBJ, UnknownReason.Kind.NATIVE, "Panama upcall"),
        new Rule("jdk.internal.misc.Unsafe", "putLong", "(JJ)V", UnknownReason.Kind.NATIVE, "raw memory"),
        new Rule("java.lang.Class", "newInstance", OBJ, UnknownReason.Kind.REFLECT, "core reflection"),
        new Rule("org.xml.sax.XMLReader", "parse", "()V", UnknownReason.Kind.REFLECT, "XXE parse"),
        new Rule("javax.xml.parsers.SAXParser", "parse", "()V", UnknownReason.Kind.REFLECT, "XXE parse")
    );

    /**
     * EVERY FIXTURE MUST PROVE ITS RULE FIRES FIRST (§E3): a row whose {@code classify} does not answer
     * {@code UNKNOWN} is asserting a kind about a rule it never reached, and would pass whatever the table
     * said. Both halves are asserted per row, and the row's justification is printed on failure.
     */
    @Test
    void everyRuleFiresAndCarriesTheKindItsShapeLicenses() {
        List<String> bad = new ArrayList<>();
        for (Rule r : concat(TABLE, SIBLINGS)) {
            Effect e = Classifier.classify(r.owner(), r.method(), r.desc());
            if (e != Effect.UNKNOWN) {
                bad.add("UNREACHED FIXTURE " + r.owner() + "." + r.method() + r.desc()
                        + " classified " + e + ", not UNKNOWN — the row asserts a kind about a rule it "
                        + "never reached");
                continue;
            }
            UnknownReason.Kind got = Classifier.unknownKind(r.owner());
            if (got != r.kind())
                bad.add(r.owner() + "." + r.method() + ": kind " + got + ", expected " + r.kind()
                        + " — " + r.why());
        }
        assertTrue(bad.isEmpty(), String.join("\n", bad));
        assertEquals(38, TABLE.size(), "one row per `return Effect.UNKNOWN` site in Classifier");
    }

    /**
     * THE CALIBRATION (§1b) — the six rules R675 MOVED, asserted as a movement rather than as a value. Set
     * {@code Classifier.unknownKind} back to a bare {@code return REFLECT} and this is the test that goes
     * red; the row above would go red too, but this one names the claim the row was filed on.
     */
    @Test
    void theDelegationAndNativeFamiliesAreNoLongerReflect() {
        for (Rule r : concat(TABLE, SIBLINGS)) {
            if (r.kind() == UnknownReason.Kind.REFLECT) continue;
            assertNotEquals(UnknownReason.Kind.REFLECT, Classifier.unknownKind(r.owner()),
                    r.owner() + " is " + r.kind() + ", not reflection: " + r.why());
        }
        // …and the class a POLICY reads, not just the raw kind — the projection is what `deny
        // Unknown[dispatch]` quantifies over, and a kind that projected back to `reflect` would move nothing.
        assertEquals("dispatch", cls("java.io.FilterInputStream"), "the 918-hole family");
        assertEquals("native", cls("com.sun.jna.Function"));
        assertEquals("native", cls("sun.misc.Unsafe"));
        assertEquals("native", cls("ai.onnxruntime.OrtSession"));
        assertEquals("native", cls("java.lang.foreign.Linker"));
        assertEquals("reflect", cls("java.lang.reflect.Method"), "the majority family does NOT move");
    }

    /**
     * THE POPULATION TRIPWIRE. A 39th {@code return Effect.UNKNOWN} added to {@link Classifier} without a
     * row in {@link #TABLE} would silently take {@code unknownKind}'s majority default — R675 recurring, one
     * rule at a time, invisibly. Nothing about the default prevents that; this does.
     */
    @Test
    void theUnknownRulePopulationHasNotChangedWithoutThisTable() throws IOException {
        Path src = Path.of("src/main/java/io/poly/candor/Classifier.java");
        assertTrue(Files.isRegularFile(src), "the classifier source must be findable from the test's working "
                + "directory or this census silently passes over nothing: " + src.toAbsolutePath());
        String s = Files.readString(src);
        assertTrue(s.length() > 100_000, "read almost no source — the census would prove nothing");
        // A STATEMENT, not a mention. Counting the bare token over the whole file counted this file's own
        // javadoc describing the rule population — 39 for 38 rules, an off-by-one that reads as a real
        // change. So: skip comment lines and require the semicolon. (The family's standing note on source
        // censuses is that `contains` over a whole file is how a check becomes vacuous or wrong; here it
        // was wrong in the loud direction, which is the lucky one.)
        int sites = 0;
        for (String line : s.split("\n")) {
            String t = line.strip();
            if (t.startsWith("*") || t.startsWith("//") || t.startsWith("/*")) continue;
            for (int i = 0; (i = t.indexOf("return Effect.UNKNOWN;", i)) >= 0; i += 22) sites++;
        }
        assertEquals(TABLE.size(), sites,
                "Classifier has " + sites + " `return Effect.UNKNOWN` rules and this test's table has "
                + TABLE.size() + ". A new Unknown rule needs (a) a row here, with a fixture that proves it "
                + "fires and the KIND its shape licenses, and (b) an entry in Classifier's "
                + "NATIVE_UNKNOWN_OWNERS / DELEGATING_STREAM_OWNERS if it is not reflection — otherwise it "
                + "takes the majority default and SOUNDNESS R675 happens again, one rule at a time.");
    }

    /** The §6.2 policy-facing class token for an owner's kind — what `deny Unknown[…]` actually filters on. */
    private static String cls(String owner) {
        return ReasonClass.of(UnknownReason.of(Classifier.unknownKind(owner), owner + ".m")).token();
    }

    private static List<Rule> concat(List<Rule> a, List<Rule> b) {
        List<Rule> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }
}
