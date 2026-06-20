package io.poly.candor;

import java.util.*;
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
        ProvValue(BasicValue base, String newType) { this(base, newType, false, declTypeOf(base), null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy) { this(base, newType, fromIndy, declTypeOf(base), null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType) { this(base, newType, fromIndy, declType, null); }
        ProvValue(BasicValue base, String newType, boolean fromIndy, String declType, String lambdaTarget) {
            this.base = base; this.newType = newType; this.fromIndy = fromIndy; this.declType = declType;
            this.lambdaTarget = lambdaTarget;
        }
        public int getSize() { return base.getSize(); }
        public boolean equals(Object o) {
            return o instanceof ProvValue p && base.equals(p.base)
                    && Objects.equals(newType, p.newType) && fromIndy == p.fromIndy
                    && Objects.equals(declType, p.declType) && Objects.equals(lambdaTarget, p.lambdaTarget);
        }
        public int hashCode() {
            return (((base.hashCode() * 31 + (newType == null ? 0 : newType.hashCode())) * 31 + (fromIndy ? 1 : 0))
                    * 31 + (declType == null ? 0 : declType.hashCode())) * 31 + (lambdaTarget == null ? 0 : lambdaTarget.hashCode());
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
                return wrap(bi.newOperation(insn), t, t);
            }
            String dt = (insn.getOpcode() == Opcodes.GETSTATIC) ? declFromDesc(((FieldInsnNode) insn).desc) : null;
            return wrap(bi.newOperation(insn), null, dt);
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
            if (insn.getOpcode() == Opcodes.GETFIELD) dt = declFromDesc(((FieldInsnNode) insn).desc);
            else if (insn.getOpcode() == Opcodes.CHECKCAST) {
                String d = ((TypeInsnNode) insn).desc; // CHECKCAST desc is an internal name (or [..] array)
                dt = (d != null && d.charAt(0) != '[' && !d.equals("java/lang/Object")) ? d : null;
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
            return new ProvValue(b, null, indy, dt, lt);
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
            if (mb.equals(a.base) && Objects.equals(mt, a.newType) && mi == a.fromIndy
                    && Objects.equals(mdt, a.declType) && Objects.equals(mlt, a.lambdaTarget)) return a;
            return new ProvValue(mb, mt, mi, mdt, mlt);
        }
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
