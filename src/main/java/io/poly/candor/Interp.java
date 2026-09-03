package io.poly.candor;

import java.util.*;
import io.poly.candor.model.Effect;
import java.util.stream.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;
import static io.poly.candor.Cha.*;
import static io.poly.candor.Literals.*;

/** The two ASM dataflow interpreters and their helpers — the TAINT pass (TaintValue/TaintInterpreter +
 *  paramSlots/argsTainted) and the PROVENANCE pass (ProvValue/ProvInterpreter + declTypeOf/
 *  monomorphicReceiver). EXTRACTED verbatim from Candor.java (refactor P2); the nested types + helpers
 *  are re-exposed to Candor as bare names via `import static io.poly.candor.Interp.*`, and read Candor
 *  state/methods via `import static io.poly.candor.Candor.*`. See REFACTOR_PLAN.md. */
final class Interp {
    /** The local-variable slots holding this method's declared parameters (excluding `this`); a load from
     *  one of these is the untrusted-input source for the taint pass. Long/double params occupy 2 slots. */
    static Set<Integer> paramSlots(MethodNode mn) {
        Set<Integer> s = new HashSet<>();
        int slot = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1; // instance methods carry `this` at slot 0
        for (Type t : Type.getArgumentTypes(mn.desc)) {
            s.add(slot);
            slot += t.getSize();
        }
        return s;
    }

    /** Is any ARGUMENT (not the receiver) of the call `min` tainted in the frame `f` before it executes? */
    static boolean argsTainted(Frame<TaintValue> f, MethodInsnNode min) {
        if (f == null) return false;
        int slots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) slots += a.getSize();
        int top = f.getStackSize();
        for (int i = 0; i < slots && i < top; i++) { // the args occupy the top `slots` stack entries
            TaintValue v = f.getStack(top - 1 - i);
            if (v != null && v.tainted) return true;
        }
        return false;
    }

    /** A dataflow value carrying ASM's type/size (`base`) plus a taint bit (derives from a parameter). */
    static final class TaintValue implements Value {
        final BasicValue base;
        final boolean tainted;
        TaintValue(BasicValue base, boolean tainted) { this.base = base; this.tainted = tainted; }
        public int getSize() { return base.getSize(); }
        public boolean equals(Object o) {
            return o instanceof TaintValue t && base.equals(t.base) && tainted == t.tainted;
        }
        public int hashCode() { return base.hashCode() * 2 + (tainted ? 1 : 0); }
    }

    /** Propagates taint over a method's dataflow: a load of a parameter slot is the source; taint flows
     *  through copies, casts, arithmetic, and method calls (StringBuilder/concat carry it). Type/size
     *  correctness is delegated to {@link BasicInterpreter} so the analyzer's frames merge soundly. */
    static final class TaintInterpreter extends Interpreter<TaintValue> {
        private final BasicInterpreter bi = new BasicInterpreter();
        private final Set<Integer> params;
        TaintInterpreter(Set<Integer> params) { super(Opcodes.ASM9); this.params = params; }
        private static TaintValue wrap(BasicValue b, boolean t) { return b == null ? null : new TaintValue(b, t); }

        public TaintValue newValue(Type type) { return wrap(bi.newValue(type), false); }
        public TaintValue newOperation(AbstractInsnNode insn) throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.newOperation(insn), false);
        }
        public TaintValue copyOperation(AbstractInsnNode insn, TaintValue value)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            int op = insn.getOpcode();
            // A load from a parameter slot IS the untrusted-input source; every other copy preserves taint.
            if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD && insn instanceof VarInsnNode vi
                    && params.contains(vi.var))
                return new TaintValue(value.base, true);
            return value;
        }
        public TaintValue unaryOperation(AbstractInsnNode insn, TaintValue value)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.unaryOperation(insn, value.base), value.tainted);
        }
        public TaintValue binaryOperation(AbstractInsnNode insn, TaintValue a, TaintValue b)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.binaryOperation(insn, a.base, b.base), a.tainted || b.tainted);
        }
        public TaintValue ternaryOperation(AbstractInsnNode insn, TaintValue a, TaintValue b, TaintValue c)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.ternaryOperation(insn, a.base, b.base, c.base), a.tainted || b.tainted || c.tainted);
        }
        public TaintValue naryOperation(AbstractInsnNode insn, List<? extends TaintValue> values)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            boolean t = false;
            List<BasicValue> bases = new ArrayList<>(values.size());
            for (TaintValue v : values) { bases.add(v.base); t |= v.tainted; }
            // The result of a call/concat/StringBuilder carries taint if any argument did.
            return wrap(bi.naryOperation(insn, bases), t);
        }
        public void returnOperation(AbstractInsnNode insn, TaintValue value, TaintValue expected) {}
        public TaintValue merge(TaintValue a, TaintValue b) {
            BasicValue mb = bi.merge(a.base, b.base);
            boolean mt = a.tainted || b.tainted; // at a control-flow join, tainted if tainted on either path
            if (mb.equals(a.base) && mt == a.tainted) return a;
            return new TaintValue(mb, mt);
        }
    }

    /** Receiver-provenance value (the soundness fix for monomorphic-dispatch fabrication). Carries ASM's
     *  type/size (`base`) plus, when this value is PROVABLY a single freshly-constructed `new T`, that
     *  type's internal name in `newType`; otherwise `newType` is null ("indeterminate" — a parameter, a
     *  field, a return value, a merge of different new-types, or anything else). A non-null `newType` is a
     *  guarantee, never a guess: it is set ONLY by `newOperation` on a NEW insn and survives only copies,
     *  loads/stores, and merges that agree on the exact same type. */
    static final class ProvValue implements Value {
        final BasicValue base;
        final String newType; // internal name of a provable `new T` receiver, or null = indeterminate
        final boolean fromIndy; // produced by an invokedynamic (a lambda/method-ref) — its body is edged at
                                // creation, so an executor hand-off of it needs no Unknown (vs a field/param)
        // The DECLARED (static) reference type of this value, internal name — captured at the points where
        // it is precise (a param/local's declared type, a NEW, a field read's descriptor, a call's return
        // type, a CHECKCAST target). The stock BasicInterpreter collapses every reference to java/lang/Object,
        // so the implicit-contract-reentry resolution (toString/equals/hashCode/compareTo over an Object-typed
        // sink argument) needs this precise type to CHA over. It is a SOUND OVER-APPROXIMATION SOURCE for CHA
        // (which already fans to subtypes); a merge of two different declared types collapses to null. NEVER
        // used to NARROW (that is newType's job, a stronger guarantee); only to seed CHA, so an imprecise
        // (over-broad) declType can only over-edge to siblings, never under-report, and a null yields no edge.
        final String declType;
        // When this value is a lambda/method-ref (fromIndy) whose impl is a PROJECT method, the body's
        // node id; else null. Lets a closed private "sink" that invokes a functional PARAM resolve the
        // SAM to the exact bodies passed at its (enumerable) call sites instead of a callback: Unknown.
        final String lambdaTarget;
        // The instance field this value was read from ("owner#name"), or null if not a GETFIELD result. Carries
        // NO allocation guarantee (newType stays null); it lets the value-provenance field-origin summary decide,
        // at a stream read, whether the field is bound only to in-scope concrete opens (VALUE-PROVENANCE-DESIGN.md
        // Phase 2). Only ever used to SUPPRESS a Phase-1 Unknown for a provably-concrete field — never to narrow.
        final String fieldOrigin;
        // SOUNDNESS R147 — THE EFFECT OF THE ACQUISITION THAT PRODUCED THIS STREAM. Set only when this value
        // is the RETURN of a call whose declared return type is one of the four abstract `java.io` stream
        // bases AND which `Classifier.classify` already charges (`Socket.getInputStream` -> Net,
        // `Process.getInputStream` -> Exec, `URLConnection.getInputStream` -> Net, …). It is the answer to
        // "what does moving bytes through this handle actually touch", carried from the acquisition site to
        // the PUTFIELD that stores it, so `Candor#computeStreamFieldSources` can key it by field and the
        // later `in.read()` in another method charges the same effect instead of reading silent-pure.
        // ALWAYS A UNION, never a single value: at a control-flow join the sound direction for a value used
        // to CHARGE is to keep BOTH origins (unlike newType/declType/fieldOrigin above, which are used to
        // NARROW and so collapse to null on disagreement). Empty set is normalised to null.
        final Set<Effect> originEffects;
        // SOUNDNESS R179 — WHEN `fromIndy` IS TRUE AND ITS PREMISE IS FALSE. `fromIndy`'s whole job is to
        // suppress the opaque-hand-off `Unknown`, on the stated ground that "the body is edged at
        // creation". For a method reference to a FUNCTIONAL INTERFACE'S OWN SAM — `Runnable::run`,
        // `task::run` — that ground does not exist: the handle names an ABSTRACT method, so the creation
        // site edges nothing, and the body actually invoked belongs to whatever receiver the higher-order
        // function supplies at call time. This field holds `owner.name` of that SAM (else null), so the
        // hand-off site can disclose exactly what the LAMBDA spelling of the same call already discloses —
        // `callback:java.lang.Runnable.run` — instead of reading silent-pure.
        final String samForwarder;
        ProvValue(BasicValue base, String newType) { this(base, newType, false, declTypeOf(base), null, null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy) { this(base, newType, fromIndy, declTypeOf(base), null, null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType) { this(base, newType, fromIndy, declType, null, null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType, String lambdaTarget) { this(base, newType, fromIndy, declType, lambdaTarget, null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType, String lambdaTarget, String fieldOrigin) {
            this(base, newType, fromIndy, declType, lambdaTarget, fieldOrigin, null);
        }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType, String lambdaTarget,
                  String fieldOrigin, Set<Effect> originEffects) {
            this(base, newType, fromIndy, declType, lambdaTarget, fieldOrigin, originEffects, null);
        }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType, String lambdaTarget,
                  String fieldOrigin, Set<Effect> originEffects, String samForwarder) {
            this.base = base; this.newType = newType; this.fromIndy = fromIndy; this.declType = declType;
            this.lambdaTarget = lambdaTarget; this.fieldOrigin = fieldOrigin;
            this.originEffects = (originEffects == null || originEffects.isEmpty()) ? null : originEffects;
            this.samForwarder = samForwarder;
        }
        public int getSize() { return base.getSize(); }
        public boolean equals(Object o) {
            return o instanceof ProvValue p && base.equals(p.base)
                    && Objects.equals(newType, p.newType) && fromIndy == p.fromIndy
                    && Objects.equals(declType, p.declType) && Objects.equals(lambdaTarget, p.lambdaTarget)
                    && Objects.equals(fieldOrigin, p.fieldOrigin)
                    && Objects.equals(originEffects, p.originEffects)
                    && Objects.equals(samForwarder, p.samForwarder);
        }
        public int hashCode() {
            return ((((((base.hashCode() * 31 + (newType == null ? 0 : newType.hashCode())) * 31 + (fromIndy ? 1 : 0))
                    * 31 + (declType == null ? 0 : declType.hashCode())) * 31 + (lambdaTarget == null ? 0 : lambdaTarget.hashCode()))
                    * 31 + (fieldOrigin == null ? 0 : fieldOrigin.hashCode()))
                    * 31 + (originEffects == null ? 0 : originEffects.hashCode()))
                    * 31 + (samForwarder == null ? 0 : samForwarder.hashCode());
        }
    }

    /** The declared OBJECT internal name of a BasicValue, or null for primitives / the bare-Object
     *  REFERENCE_VALUE / null-type — i.e. only a usefully-specific reference type. */
    static String declTypeOf(BasicValue b) {
        if (b == null) return null;
        Type t = b.getType();
        if (t == null || t.getSort() != Type.OBJECT) return null; // primitives, arrays, void — no contract reentry
        String n = t.getInternalName();
        return n.equals("java/lang/Object") ? null : n; // bare Object carries no resolvable override
    }

    /** Tracks, per stack/local value, whether it is PROVABLY a single `new T` — the receiver-provenance
     *  dataflow that lets an invokevirtual on a freshly-allocated, single-typed receiver resolve to the
     *  one method T dispatches, SKIPPING the CHA sibling fan-out (the monomorphic fabrication fix). Type/
     *  size correctness is delegated to {@link BasicInterpreter} so frames merge soundly. SOUND BY
     *  CONSTRUCTION: only `newOperation` on a NEW insn mints a `newType`; every other production (params
     *  via `newValue`, field/array/return values via the base interpreter, constants) is indeterminate;
     *  and `merge` of two DIFFERENT new-types (or a new with a non-new) collapses to indeterminate — so a
     *  genuinely polymorphic receiver (param/field/branch-merged) NEVER narrows, keeping the CHA. */
    static final class ProvInterpreter extends Interpreter<ProvValue> {
        private final BasicInterpreter bi = new BasicInterpreter();
        ProvInterpreter() { super(Opcodes.ASM9); }
        private static ProvValue wrap(BasicValue b, String t) { return b == null ? null : new ProvValue(b, t); }
        // Build with an EXPLICIT declared type — used where the insn carries a precise reference type the
        // BasicInterpreter would have collapsed to bare Object (field reads, call returns, casts, NEW).
        private static ProvValue wrap(BasicValue b, String newType, String declType) {
            return b == null ? null : new ProvValue(b, newType, false, declType);
        }
        private static ProvValue wrapField(BasicValue b, String declType, String fieldOrigin) {
            return b == null ? null : new ProvValue(b, null, false, declType, null, fieldOrigin);
        }
        /** The OBJECT-internal-name a type descriptor declares, or null if not a usefully-specific object
         *  type (primitives / void / array / bare Object). Used to seed declType from a field/return desc. */
        private static String declFromDesc(String desc) {
            if (desc == null) return null;
            try {
                Type t = Type.getType(desc);
                if (t.getSort() != Type.OBJECT) return null;
                String n = t.getInternalName();
                return n.equals("java/lang/Object") ? null : n;
            } catch (Throwable t) { return null; }
        }

        public ProvValue newValue(Type type) {
            // The Analyzer calls this to SEED method-param / this locals with their DECLARED types — `type`
            // is precise here, but bi.newValue collapses every object ref to REFERENCE_VALUE (bare Object),
            // so declTypeOf(base) loses it. Capture the precise declared object type directly from `type`.
            // (A null/primitive/array/Object type → null declType, as declFromDesc enforces.)
            BasicValue b = bi.newValue(type);
            if (b == null) return null;
            String dt = (type != null) ? declFromDesc(type.getDescriptor()) : null;
            return new ProvValue(b, null, false, dt);
        }
        public ProvValue newOperation(AbstractInsnNode insn) throws org.objectweb.asm.tree.analysis.AnalyzerException {
            // The NEW opcode (and ONLY it among newOperation's insns) yields an UNINITIALIZED single-typed
            // reference; that type is the provable receiver type. LDC / GETSTATIC / constants / etc. carry
            // no allocation-site guarantee, so they stay indeterminate. GETSTATIC's field desc IS a precise
            // declared type, though — capture it for declType (a static field holding a project type whose
            // toString is effectful, fed to a sink). The NEW desc is both newType AND declType.
            if (insn.getOpcode() == Opcodes.NEW) {
                String t = ((TypeInsnNode) insn).desc;
                // SOUNDNESS R147 — a SELF-SOURCING concrete stream (`new FileInputStream`) is an acquisition
                // too, and its origin has to ride on the VALUE rather than be re-derived from `newType` at
                // the store. Measured: `this.in = net ? sock.getInputStream() : new FileInputStream(f)`
                // merges a newType-bearing value with a newType-less one, so `newType` COLLAPSES to null at
                // the join (correct — it is a narrowing guarantee) and a store-side re-derivation loses the
                // Fs half in silence. Carried here it unions with the socket's Net like any other origin.
                Effect ce = selfSourcingCtorEffect(t);
                BasicValue nb = bi.newOperation(insn);
                return nb == null ? null
                        : new ProvValue(nb, t, false, t, null, null, ce == null ? null : EnumSet.of(ce));
            }
            if (insn.getOpcode() == Opcodes.GETSTATIC) {
                // ⟨0.35⟩ A static field's read is a field-origin carrier too, exactly like GETFIELD below —
                // see collectFieldLambdaBindings's doc for why treating this as merely "inert" was wrong:
                // a static field re-read in its OWN declaring class (the ordinary case) was silently
                // dropping the stored lambda's effect. fieldKey normalizes owner+name to the declaring
                // class, the same normalization the write side now applies.
                FieldInsnNode fi = (FieldInsnNode) insn;
                return wrapField(bi.newOperation(insn), declFromDesc(fi.desc), fieldKey(fi.owner, fi.name));
            }
            return wrap(bi.newOperation(insn), null, null);
        }
        public ProvValue copyOperation(AbstractInsnNode insn, ProvValue value) { return value; }
        public ProvValue unaryOperation(AbstractInsnNode insn, ProvValue value)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            // A unary op (cast, conversion, getfield, arraylength, …) never preserves the allocation-site
            // guarantee: even CHECKCAST of a `new T` keeps T, but a field read off it does not — and we
            // can't tell them apart cheaply, so conservatively drop newType to indeterminate. (The sound
            // direction: dropping a true `new T` only FORGOES a narrow and keeps the CHA over-approximation.)
            // BUT capture the PRECISE declared type the insn names — a GETFIELD's field desc and a CHECKCAST's
            // target — since the implicit-reentry CHA seeds off declType (an over-broad declType only
            // over-edges to siblings, never under-reports). A primitive conversion / arraylength yields null.
            BasicValue b = bi.unaryOperation(insn, value.base);
            String dt = null;
            if (insn.getOpcode() == Opcodes.GETFIELD) {
                FieldInsnNode fi = (FieldInsnNode) insn;
                // Carry the field identity so the value-provenance summary can decide, at a stream read, whether
                // this field is bound only to in-scope concrete opens (Phase 2). newType stays null (no alloc).
                // fieldKey normalizes to the DECLARING class — see Cha.fieldKey's doc: the class an inherited
                // field's GETFIELD names as `owner` need not be the class its PUTFIELD names.
                return wrapField(b, declFromDesc(fi.desc), fieldKey(fi.owner, fi.name));
            }
            if (insn.getOpcode() == Opcodes.CHECKCAST) {
                String d = ((TypeInsnNode) insn).desc; // CHECKCAST desc is an internal name (or [..] array)
                dt = (d != null && d.charAt(0) != '[' && !d.equals("java/lang/Object")) ? d : null;
                // A CHECKCAST is the SAME value with a narrower static type — the acquisition it came from
                // is unchanged, so R147's origin must survive it (`(InputStream) obj` after a socket get).
                return b == null ? null : new ProvValue(b, null, false, dt, null, null, value.originEffects,
                        value.samForwarder);
            }
            return wrap(b, null, dt);
        }
        public ProvValue binaryOperation(AbstractInsnNode insn, ProvValue a, ProvValue b)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            // AALOAD (array element read) yields the array's component type — but BasicInterpreter collapses
            // it to Object, and we don't track array component types, so declType stays null (sound: no edge).
            return wrap(bi.binaryOperation(insn, a.base, b.base), null);
        }
        public ProvValue ternaryOperation(AbstractInsnNode insn, ProvValue a, ProvValue b, ProvValue c)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            return wrap(bi.ternaryOperation(insn, a.base, b.base, c.base), null);
        }
        public ProvValue naryOperation(AbstractInsnNode insn, List<? extends ProvValue> values)
                throws org.objectweb.asm.tree.analysis.AnalyzerException {
            List<BasicValue> bases = new ArrayList<>(values.size());
            for (ProvValue v : values) bases.add(v.base);
            // A call/multianewarray result is never a tracked allocation site (its return value's runtime
            // type is unknown to a syntactic pass) — indeterminate `newType`. But an INVOKEDYNAMIC result
            // IS a lambda/method-ref whose body candor edges at this creation site, so flag it: an executor
            // hand-off of a lambda needs no Unknown (the body is already captured), unlike an opaque
            // field/param task. (fromIndy is read ONLY at the hand-off site — monomorphicReceiver, which
            // reads newType, is unaffected.)
            BasicValue b = bi.naryOperation(insn, bases);
            boolean indy = insn.getOpcode() == Opcodes.INVOKEDYNAMIC;
            if (b == null) return null;
            // A call's RETURN type is precise (the method descriptor) — capture it for declType, so a value
            // produced by `factory()` and fed to a sink resolves its declared type's contract override.
            String dt = null;
            if (insn instanceof MethodInsnNode mi) dt = declFromDesc(Type.getReturnType(mi.desc).getDescriptor());
            // A lambda/method-ref creation: capture the PROJECT impl body so a closed sink can resolve it.
            String lt = indy && insn instanceof InvokeDynamicInsnNode idin ? indyLambdaTarget(idin) : null;
            // SOUNDNESS R147 — carry the ACQUISITION's effect on a stream handed back by a classified call.
            // SOUNDNESS R179 — and, for an indy, whether it merely FORWARDS to a bodiless SAM.
            String sf = indy && insn instanceof InvokeDynamicInsnNode idin2 ? samForwarderTarget(idin2) : null;
            return new ProvValue(b, null, indy, dt, lt, null, acquisitionEffects(insn), sf);
        }
        public void returnOperation(AbstractInsnNode insn, ProvValue value, ProvValue expected) {}
        public ProvValue merge(ProvValue a, ProvValue b) {
            BasicValue mb = bi.merge(a.base, b.base);
            // CRITICAL for soundness: a control-flow join keeps the `new T` guarantee ONLY when BOTH paths
            // bring the SAME new-type; a new-vs-new(other), a new-vs-indeterminate, or any disagreement
            // collapses to indeterminate, so a branch-merged receiver (`if (c) new Base() else new Dirty()`)
            // is NOT monomorphic and the CHA fan-out is preserved.
            String mt = Objects.equals(a.newType, b.newType) ? a.newType : null;
            // declType likewise keeps a precise type only when BOTH paths agree (else null = no reentry edge).
            // This is the SOUND direction for an over-approximation source: a disagreeing merge drops to "no
            // edge", which can only forgo an edge, never fabricate one onto an unrelated type.
            String mdt = Objects.equals(a.declType, b.declType) ? a.declType : null;
            // a join is "definitely a lambda" only when BOTH paths are — else treat as opaque (a lambda-vs-
            // field merge must NOT be skipped at the hand-off site).
            boolean mi = a.fromIndy && b.fromIndy;
            // a join resolves to ONE lambda body only when both paths agree on it; a disagreement collapses
            // to null (opaque), so a closed sink fed two different lambdas via a branch stays unresolved
            // unless BOTH call sites are separately collected (they are — collection is per call site).
            String mlt = Objects.equals(a.lambdaTarget, b.lambdaTarget) ? a.lambdaTarget : null;
            // fieldOrigin likewise survives a join ONLY when both paths read the SAME field — a field-vs-param
            // (or field-vs-other-field) merge collapses to null, so the value-provenance suppression never
            // fires on a joined value that can be an external (non-field) operand (would be a silent under-report).
            String mfo = Objects.equals(a.fieldOrigin, b.fieldOrigin) ? a.fieldOrigin : null;
            // SOUNDNESS R147 — originEffects UNIONS at a join, it does not collapse. It is used to CHARGE an
            // effect on a later read of the stored handle, so dropping one arm's origin would silently lose
            // the effect of the branch that acquired it (`in = c ? sock.getInputStream() : new
            // FileInputStream(f)` must charge BOTH). Every other field here is used to NARROW, where the
            // sound direction is the opposite one — collapse to null.
            Set<Effect> moe = unionOrigins(a.originEffects, b.originEffects);
            // SOUNDNESS R179 — samForwarder SURVIVES a join whenever EITHER path carries one, for the same
            // reason as originEffects: it is used to DISCLOSE, so losing it on one arm is the silent
            // direction. Ties are broken lexicographically only so the choice of REASON STRING is
            // deterministic across runs — whether the disclosure fires does not depend on which is picked.
            String msf = a.samForwarder == null ? b.samForwarder
                    : b.samForwarder == null ? a.samForwarder
                    : (a.samForwarder.compareTo(b.samForwarder) <= 0 ? a.samForwarder : b.samForwarder);
            if (mb.equals(a.base) && Objects.equals(mt, a.newType) && mi == a.fromIndy
                    && Objects.equals(mdt, a.declType) && Objects.equals(mlt, a.lambdaTarget)
                    && Objects.equals(mfo, a.fieldOrigin) && Objects.equals(moe, a.originEffects)
                    && Objects.equals(msf, a.samForwarder)) return a;
            return new ProvValue(mb, mt, mi, mdt, mlt, mfo, moe, msf);
        }
    }

    /** SOUNDNESS R147 — the effect of a STREAM ACQUISITION, or null when this instruction is not one.
     *
     *  <p>An acquisition is a call whose DECLARED RETURN TYPE is one of the four abstract {@code java.io}
     *  stream bases and which {@link Classifier#classify} already charges an effect for. That is the whole
     *  test, and it is deliberately the classifier's own answer rather than a second table of socket
     *  getters (§G — ask the authority, never reimplement it): whatever `Socket.getInputStream` /
     *  `SSLSocket.getInputStream` / `URLConnection.getInputStream` / `Process.getInputStream` /
     *  `ZipFile.getInputStream` are charged at their acquisition site is exactly what a later read through
     *  the stored handle is charged, so the two answers cannot drift apart (§F1 q3).
     *
     *  <p>The RETURN-TYPE gate is what keeps this from firing on every classified call in the program: it
     *  matches only the shape whose effect is otherwise lost — an effectful call that hands back an opaque
     *  handle to be moved through later. A concrete return type (`FileInputStream`) needs nothing, because
     *  the field then carries that type and the classifier fires on the read itself. */
    static Set<Effect> acquisitionEffects(AbstractInsnNode insn) {
        if (!(insn instanceof MethodInsnNode mi)) return null;
        String ret;
        try {
            Type rt = Type.getReturnType(mi.desc);
            if (rt.getSort() != Type.OBJECT) return null;   // void / primitive / array — never a stream handle
            ret = rt.getInternalName();
        } catch (Throwable t) { return null; }
        if (ret == null || !isAbstractStreamType(ret)) return null;
        Effect e = Classifier.classify(mi.owner.replace('/', '.'), mi.name, mi.desc);
        return e == null ? null : EnumSet.of(e);
    }

    /** The four abstract {@code java.io} stream bases — the declared types a handle whose real source is
     *  invisible to the classifier travels as. Kept beside {@link Candor#isStreamFieldDesc}, which names
     *  the same four as FIELD descriptors. */
    static boolean isAbstractStreamType(String internalName) {
        return internalName.equals("java/io/InputStream") || internalName.equals("java/io/OutputStream")
                || internalName.equals("java/io/Reader") || internalName.equals("java/io/Writer");
    }

    /** Union of two origin sets, normalising empty to null. Union — not intersection, not first-wins —
     *  because this set CHARGES. */
    static Set<Effect> unionOrigins(Set<Effect> a, Set<Effect> b) {
        if (a == null) return b;
        if (b == null) return a;
        if (a.containsAll(b)) return a;
        if (b.containsAll(a)) return b;
        EnumSet<Effect> u = EnumSet.copyOf(a);
        u.addAll(b);
        return u;
    }

    /** The provable single `new T` receiver internal name of the call `min` in frame `f`, or null if the
     *  receiver is NOT provably a single freshly-constructed type (a param/field/return/merge — the
     *  genuinely polymorphic case that MUST keep the CHA). The receiver is the stack entry just below the
     *  call's arguments. */
    static String monomorphicReceiver(Frame<ProvValue> f, MethodInsnNode min) {
        if (f == null) return null;
        int argSlots = 0;
        for (Type a : Type.getArgumentTypes(min.desc)) argSlots += a.getSize();
        int top = f.getStackSize();
        int recvIdx = top - 1 - argSlots; // below the args sits the receiver
        if (recvIdx < 0) return null;
        ProvValue rv = f.getStack(recvIdx);
        return rv == null ? null : rv.newType;
    }
}
