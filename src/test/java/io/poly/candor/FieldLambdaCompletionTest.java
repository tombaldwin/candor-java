package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * ⟨0.35⟩ SPEC §4 "A NON-EMPTY CANDIDATE SET IS NOT A COMPLETE ONE" — teeth for
 * {@link Cha#collectFieldLambdaBindings} / {@link Cha#fieldBoundImplementors}.
 *
 * <p>THE DEFECT, measured on the published 0.34.0 jar (candor-spec PART 87). A lambda or method
 * reference stored in a field and invoked later resolved to NOTHING the moment ANY OTHER, completely
 * unrelated class also implemented the same interface: {@code chaTargets} went from empty (honest
 * {@code callback:}/{@code dispatch:} Unknown) to non-empty-and-narrow (silently resolves to the named
 * implementor ALONE, dropping the field's own lambda edge) — and since the caller then had zero
 * effects, it vanished from {@code functions[]} entirely (indistinguishable from a genuinely pure
 * function). `deny Unknown` flipped exit 1 -> exit 0. Reproduces through three spellings — a stored
 * lambda, a method reference (worse: no synthetic body to attribute at all), and a user-defined
 * interface (routes through {@code dispatch:}, not {@code callback:}) — so a fix shaped for only one
 * closes a third of it; all three are exercised below with the SAME unrelated-implementor shape PART 87
 * uses.
 *
 * <p>THE REVERT TEST. Every {@code *Completes} case here fails loudly without the fix: reverting
 * {@link Cha#fieldBoundImplementors}'s call site in {@code Candor.virtualDispatch} makes the caller
 * disappear from the scan result (an absent key, not a wrong one — see {@code eff()}'s
 * {@code EffectSet.empty()} default, which reads identically to "genuinely pure" and is why this test
 * asserts the effect is PRESENT, never merely "not absent").
 *
 * <p>THE OVER-CHARGE CONTROLS, first (candor's own convention: this fix makes effects FLOW, and 4 of the
 * last 5 fabrication-shaped fixes in this project introduced the class they closed).
 * {@code pureLambdaGainsNothingEvenWithUnrelatedImplementor} is the direct PART 87 analogue: a pure
 * lambda through the identical shape must not gain an effect merely because an unrelated EFFECTFUL
 * implementor exists elsewhere. {@code unrelatedFieldsEffectDoesNotCrossOver} is the stronger, field-
 * scoped version PART 87 does not itself carry: a first version of this fix (registered every
 * lambda/method-ref project-wide under (owner,name,desc), unioned straight into {@code chaTargets})
 * passed PART 87 but attributed one field's effect onto a SIBLING field's dispatch, and separately broke
 * 4 existing {@code PrivateFunctionalParamForwardingTest} cases by short-circuiting the private
 * functional-param forwarding mechanism's opaque-call-site bail — {@code taintedFieldKeepsUnknown} below
 * is the direct fixture for that failure mode (a field written from BOTH a lambda and an opaque source
 * must keep the honest Unknown, never silently resolve to just the lambda it happens to know about).
 */
class FieldLambdaCompletionTest {

    private static Map<String, EffectSet> compileAndScan(Map<String, String> sources) throws Exception {
        Path out = TestCompiler.compile(sources);
        try {
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** Spelling 1 — a stored INLINE LAMBDA, JDK interface (Runnable), with an unrelated pure implementor
     *  present (the exact PART 87 "one implementor" shape): the candidate set must COMPLETE — the
     *  caller's effects must include Fs, not merely "not be silently pure". */
    @Test
    void storedLambdaCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl1.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private Runnable task;",
                "  public void install(Store s) { this.task = () -> s.write(); }",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.FS),
                "a stored lambda's Fs must reach its caller even with an unrelated implementor present, got "
                + r.get("Widget.fire"));
        assertFalse(eff(r, "Widget.fire").contains(Effect.UNKNOWN),
                "the candidate set was COMPLETED — no Unknown needed, got " + r.get("Widget.fire"));
    }

    /** Spelling 2 — a BOUND INSTANCE METHOD REFERENCE, JDK interface. No synthetic {@code lambda$…} body
     *  exists at all here — the metafactory handle points straight at {@code Store.write} — so this is
     *  the case a fix that only recognises {@code lambda$} bodies would miss. */
    @Test
    void methodReferenceCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl2.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private Runnable task;",
                "  public void install(Store s) { this.task = s::write; }",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.FS),
                "a method reference's Fs must reach its caller even with an unrelated implementor present, got "
                + r.get("Widget.fire"));
    }

    /** Spelling 3 — a USER-DEFINED functional interface (routes through {@code dispatch:}, not
     *  {@code callback:}), stored lambda. */
    @Test
    void userDefinedInterfaceCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Task.java", "public interface Task { void go(); }",
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl3.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private Task task;",
                "  public void install(Store s) { this.task = () -> s.write(); }",
                "  public void fire() { if (task != null) task.go(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Task { public static int n; @Override public void go() { n++; } }")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.FS),
                "a user-defined-interface lambda's Fs must reach its caller even with an unrelated implementor "
                + "present, got " + r.get("Widget.fire"));
    }

    /** OVER-CHARGE CONTROL 1 (PART 87's own control, mirrored here as a revert-tested unit fixture): the
     *  IDENTICAL shape with a PURE lambda must gain NOTHING, even though the unrelated Repaint implementor
     *  is effectful this time — proving the fix unions the FIELD's own write-set, not "any implementor of
     *  the interface". */
    @Test
    void pureLambdaGainsNothingEvenWithUnrelatedEffectfulImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Quiet.java", "public class Quiet { public static int n; public void bump() { n++; } }",
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private Runnable task;",
                "  public void install(Quiet q) { this.task = () -> q.bump(); }",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Repaint implements Runnable {",
                "  @Override public void run() { try { Files.write(Paths.get(\"/tmp/fl4.txt\"), \"x\".getBytes()); } catch (IOException e) {} }",
                "}")));
        assertFalse(eff(r, "Widget.fire").contains(Effect.FS),
                "a pure lambda through the same shape must not gain Fs from an unrelated EFFECTFUL "
                + "implementor, got " + r.get("Widget.fire"));
    }

    /** OVER-CHARGE CONTROL 2 — the field-scoped strengthening PART 87 does not itself carry. TWO SEPARATE
     *  fields of the SAME interface type in the SAME class: {@code quiet} is always assigned a pure
     *  lambda, {@code loud} is always assigned an effectful one. {@code fireQuiet} must not pick up
     *  {@code loud}'s Fs merely because both are Runnable — a caller must never gain an effect through a
     *  field it never dispatches through. (A first version of this fix, which unioned every lambda
     *  project-wide under (owner,name,desc) rather than binding per-FIELD, would have failed this.) */
    @Test
    void unrelatedFieldsEffectDoesNotCrossOver() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Widget.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Widget {",
                "  private Runnable quiet;",
                "  private Runnable loud;",
                "  public void install() {",
                "    this.quiet = () -> { int x = 1 + 1; };",
                "    this.loud = () -> { try { Files.write(Paths.get(\"/tmp/fl5.txt\"), \"x\".getBytes()); } catch (IOException e) {} };",
                "  }",
                "  public void fireQuiet() { if (quiet != null) quiet.run(); }",
                "  public void fireLoud() { if (loud != null) loud.run(); }",
                "}")));
        assertFalse(eff(r, "Widget.fireQuiet").contains(Effect.FS),
                "fireQuiet dispatches only through the PURE field — it must not gain the sibling field's Fs, "
                + "got " + r.get("Widget.fireQuiet"));
        assertTrue(eff(r, "Widget.fireLoud").contains(Effect.FS),
                "fireLoud's own field IS effectful and must still resolve, got " + r.get("Widget.fireLoud"));
    }

    /** TAINT CONTROL — the fixture for the failure mode a project-wide (owner,name,desc) union actually
     *  hit: a field assigned from BOTH a project lambda AND an opaque (unrecognisable) source must keep
     *  the honest Unknown, never silently resolve to just the lambda it happens to recognise — the
     *  opaque assignment could be anything. Mirrors {@code PrivateFunctionalParamForwardingTest
     *  .opaqueCallSiteKeepsUnknown}'s property, at the FIELD granularity this fix actually touches. */
    @Test
    void taintedFieldKeepsUnknown() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private Runnable task;",
                "  public void installLambda() { this.task = () -> {}; }",
                "  public void installOpaque(Runnable r) { this.task = r; }",  // opaque source — taints the field
                "  public void fire() { if (task != null) task.run(); }",
                "}")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.UNKNOWN),
                "a field with an opaque assignment anywhere must keep Unknown — the lambda assignment "
                + "elsewhere must not silently vouch for the whole field, got " + r.get("Widget.fire"));
    }
}
