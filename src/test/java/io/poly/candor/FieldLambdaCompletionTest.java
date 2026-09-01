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

    // ------------------------------------------------------------------------------------------------
    // ⟨0.35⟩ FOLLOW-UP — two ordinary Java shapes an adversarial review found the fixture above never
    // exercised: a STATIC field (GETSTATIC was never tagged with fieldOrigin at all — a totally separate
    // omission from the GETFIELD-owner-mismatch bug below, but the SAME visible symptom) and an
    // INHERITED field (a base class's PUTFIELD and a subclass's GETFIELD of the identical storage name
    // DIFFERENT owners in their own constant pools, so the write-side key and the read-side key never
    // matched). Both reproduced on the PUBLISHED 0.34.0 jar AND at this fix's own pre-image HEAD.
    //
    // THE ENUMERATION RUN before writing the fix (candor-java owns this vein; do not re-derive it — see
    // Cha.fieldKey's doc for the mechanism, and BACKLOG.md for the one shape found NOT to close): instance
    // same-class (already covered above); STATIC same-class; INSTANCE inherited, base writes / subclass
    // reads; the REVERSE direction (subclass writes / base reads via an inherited method); a field written
    // through a SETTER; a field accessed via a WIDER STATIC TYPE than its declaring class (`s.task = …`
    // where `s` is declared `Sub` but `task` lives on `Base`); a field on an INTERFACE (implicitly static
    // final) read through an IMPLEMENTING class; a field written in a CONSTRUCTOR/static initializer; a
    // field accessed via `super.`. `javap -v` on each shape (recorded in the session, not reproduced here)
    // confirmed the owner javac emits is the ACCESS SITE's class, not necessarily the DECLARING class —
    // Cha.fieldKey normalizes both sides to the declaring class via the same resolutionOrder walk CHA
    // already trusts for methods, which is why one fix (plus tagging GETSTATIC) closes every shape below.
    // ------------------------------------------------------------------------------------------------

    /** STATIC field, same class — the simplest possible case, and it still vanished pre-fix because
     *  GETSTATIC never carried fieldOrigin at all (the doc used to call this "inert, not wrong"; it was
     *  wrong). No inheritance, no cross-class owner mismatch — isolates the GETSTATIC-tagging half of the
     *  fix from the fieldKey-normalization half exercised by the tests below. */
    @Test
    void staticFieldCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl6.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private static Runnable task;",
                "  public static void install(Store s) { task = () -> s.write(); }",
                "  public static void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.FS),
                "a static field's stored lambda must reach its caller, got " + r.get("Widget.fire"));
    }

    /** INHERITED field — BASE writes (in an instance method), SUBCLASS reads (inherited, unqualified).
     *  `javap -v` confirms `Base.install`'s PUTFIELD names owner=Base while `Sub.fire`'s GETFIELD of the
     *  identical `task` names owner=Sub — the exact mismatch {@link Cha#fieldKey} exists to normalize. */
    @Test
    void baseWritesSubclassReadsCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl7.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Base.java", String.join("\n",
                "public class Base {",
                "  protected Runnable task;",
                "  public void install(Store s) { this.task = () -> s.write(); }",
                "}"),
            "Sub.java", String.join("\n",
                "public class Sub extends Base {",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Sub.fire").contains(Effect.FS),
                "an inherited field's stored lambda must reach a subclass caller, got " + r.get("Sub.fire"));
    }

    /** INHERITED field, the REVERSE direction — SUBCLASS writes `this.task` (inherited, unqualified;
     *  `javap -v` shows owner=Sub there), BASE reads AND DISPATCHES it directly in its own inherited
     *  method (`task.run()`, owner=Base on the GETFIELD) — deliberately NOT through a getter that returns
     *  it, which is a separate, much larger, already-tracked gap (field provenance does not currently
     *  survive a method-call return boundary at all — see BACKLOG.md; it reproduces even same-class, on
     *  the published 0.34.0 jar, with no inheritance involved, and is out of scope for this fix). Here the
     *  dispatch site itself is the GETFIELD, so this isolates the reverse-direction owner-mismatch this
     *  fix targets from that unrelated interprocedural-provenance gap. Not the direction the review named,
     *  but the audit-boundary rule says to check the sibling: a fix that patched only "subclass reads a
     *  base-written field" could still miss this direction if it normalized one side and not the other. */
    @Test
    void subclassWritesBaseReadsCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl8.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Base.java", String.join("\n",
                "public class Base {",
                "  protected Runnable task;",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Sub.java", String.join("\n",
                "public class Sub extends Base {",
                "  public void install(Store s) { this.task = () -> s.write(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Base.fire").contains(Effect.FS),
                "a subclass-written inherited field, dispatched directly in an inherited base method, must "
                + "still resolve, got " + r.get("Base.fire"));
    }

    /** A field written through a `super.field` reference. `javap -v` shows this already names the
     *  syntactic superclass as owner (agreeing with the declaring class here), but the fix must not rely
     *  on that agreement holding for every JVM/javac — {@link Cha#fieldKey} resolves it structurally
     *  either way. */
    @Test
    void superFieldWriteCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl9.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Base.java", "public class Base { protected Runnable task; }",
            "Sub.java", String.join("\n",
                "public class Sub extends Base {",
                "  public void install(Store s) { super.task = () -> s.write(); }",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Sub.fire").contains(Effect.FS),
                "a lambda written via super.field must still reach the reading caller, got " + r.get("Sub.fire"));
    }

    /** A field accessed through a WIDER static type than its declaring class — `s.task = …` where `s` is
     *  declared `Sub` but `task` is declared on `Base`. javac's PUTFIELD names owner=Sub here (the
     *  syntactic reference type), not Base, a THIRD spelling of the owner-mismatch class distinct from
     *  plain inheritance. */
    @Test
    void fieldWriteThroughSubtypeReferenceCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl10.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Base.java", "public class Base { protected Runnable task; }",
            "Sub.java", String.join("\n",
                "public class Sub extends Base {",
                "  public void install(Sub s, Store store) { s.task = () -> store.write(); }",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Sub.fire").contains(Effect.FS),
                "a lambda written through a subtype-typed reference must still reach the reading caller, got "
                + r.get("Sub.fire"));
    }

    /** A functional-interface field DECLARED ON AN INTERFACE (implicitly `public static final`), assigned
     *  in the interface's own implicit static initializer, and READ through an IMPLEMENTING CLASS
     *  (`Impl.K`) rather than the interface itself (`Iface.K`) — javac's GETSTATIC there names owner=Impl,
     *  not the declaring interface, the same class of mismatch as inheritance but for statics. */
    @Test
    void interfaceStaticFieldReadThroughImplementorCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl11.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Iface.java", String.join("\n",
                "public interface Iface {",
                "  Runnable K = () -> { try { new Store().write(); } catch (Throwable t) {} };",
                "}"),
            "ImplOfIface.java", "public class ImplOfIface implements Iface {}",
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  public void fire() { ImplOfIface.K.run(); }",  // reads K through the IMPLEMENTING class
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.FS),
                "an interface static field's lambda read through an implementing class must still reach the "
                + "caller, got " + r.get("Widget.fire"));
    }

    /** A field written through a SETTER method (not `this.field = …` inline at the call site) and written
     *  in a CONSTRUCTOR on a different clean path — confirms the write-side scan (which walks every
     *  method, `<init>` included) sees a PUTFIELD wherever it textually lives, not just at an inline
     *  assignment shape. */
    @Test
    void fieldWrittenThroughSetterAndConstructorCompletesEvenWithUnrelatedImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Store.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Store { public void write() { try { Files.write(Paths.get(\"/tmp/fl12.txt\"), \"x\".getBytes()); } catch (IOException e) {} } }"),
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private Runnable task;",
                "  public Widget() { this.task = () -> { int z = 1 + 1; }; }",   // clean write #1: <init>
                "  public void setTask(Store s) { this.task = () -> s.write(); }", // clean write #2: setter
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "public class Repaint implements Runnable { public static int n; @Override public void run() { n++; } }")));
        assertTrue(eff(r, "Widget.fire").contains(Effect.FS),
                "a lambda installed via a setter (unioned with a constructor's own clean write) must reach "
                + "the caller, got " + r.get("Widget.fire"));
    }

    /** OVER-CHARGE CONTROL 3 — the STATIC-field analogue of {@code pureLambdaGainsNothing…}: now that
     *  static fields are bound, a PURE static-field lambda must not gain Fs merely because an unrelated
     *  EFFECTFUL Runnable also exists in the project. This is the exact shape the review's over-charge
     *  report used (Widget.task always a pure lambda; Repaint effectful) — it flipped `deny Fs
     *  Widget.fire` 1 -> 0 once the static-field write became bound, since the field is no longer tainted
     *  through to the unrelated-implementor CHA fallback. */
    @Test
    void pureStaticLambdaGainsNothingEvenWithUnrelatedEffectfulImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Widget.java", String.join("\n",
                "public class Widget {",
                "  private static Runnable task;",
                "  public static void install() { task = () -> { int z = 1 + 1; }; }",
                "  public static void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Repaint implements Runnable {",
                "  @Override public void run() { try { Files.write(Paths.get(\"/tmp/fl13.txt\"), \"x\".getBytes()); } catch (IOException e) {} }",
                "}")));
        assertFalse(eff(r, "Widget.fire").contains(Effect.FS),
                "a pure lambda in a STATIC field must not gain Fs from an unrelated EFFECTFUL implementor, got "
                + r.get("Widget.fire"));
    }

    /** OVER-CHARGE CONTROL 4 — the INHERITED-field analogue: a pure lambda stored in a base-declared field
     *  and read through a subclass must not gain Fs from an unrelated effectful implementor either, now
     *  that inherited-field binding closes the owner-mismatch that used to leave it tainted-through-to-CHA. */
    @Test
    void pureInheritedLambdaGainsNothingEvenWithUnrelatedEffectfulImplementor() throws Exception {
        Map<String, EffectSet> r = compileAndScan(Map.of(
            "Base.java", String.join("\n",
                "public class Base {",
                "  protected Runnable task;",
                "  public void install() { this.task = () -> { int z = 1 + 1; }; }",
                "}"),
            "Sub.java", String.join("\n",
                "public class Sub extends Base {",
                "  public void fire() { if (task != null) task.run(); }",
                "}"),
            "Repaint.java", String.join("\n",
                "import java.io.*; import java.nio.file.*;",
                "public class Repaint implements Runnable {",
                "  @Override public void run() { try { Files.write(Paths.get(\"/tmp/fl14.txt\"), \"x\".getBytes()); } catch (IOException e) {} }",
                "}")));
        assertFalse(eff(r, "Sub.fire").contains(Effect.FS),
                "a pure lambda in an INHERITED field must not gain Fs from an unrelated EFFECTFUL implementor, "
                + "got " + r.get("Sub.fire"));
    }
}
