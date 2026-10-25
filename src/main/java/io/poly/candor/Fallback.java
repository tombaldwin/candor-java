package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;
import java.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.analysis.Frame;

/**
 * CALL-TARGET ROUND 2, HALF 2 — THE DISCLOSURE FALLBACK, MEASURED AND NOT SHIPPED. {@code CANDOR_SITE_FALLBACK=A|B}
 * (unset: off — the default, and the only setting a release runs). At a site the JDK site table RECOGNISES whose
 * hook cannot be resolved — the operand the hook runs on is untyped ({@code Object}, or no static type), or its
 * candidate set is past the CHA bound — option A discloses {@code Unknown[dispatch:<owner>.<member>]} for every hook
 * class; option B only where the hooked member is not formatting/equality/hashing/cloning (the class §4's
 * conventionally-pure MAY still covers under B). The proposal is {@code candor-spec/proposals/
 * call-target-site-and-wire.md} §1.3; Tom chooses from the numbers this produces ({@code CANDOR_SITE_FALLBACK_COUNT=1}
 * prints one {@code SITEFB} line per recognised site to stderr, with its class and whether it resolved).
 */
final class Fallback {
    private Fallback() {}

    static final String MODE = System.getenv("CANDOR_SITE_FALLBACK");
    static final boolean COUNT = System.getenv("CANDOR_SITE_FALLBACK_COUNT") != null;

    /** The §1.4 class of a hooked member: A-only (format/eq/hash/clone) or bound under both options. */
    static String klass(JdkSites.Hook h) {
        String m = h.member();
        if (m.equals("toString()Ljava/lang/String;")) return "format";
        if (m.equals("equals(Ljava/lang/Object;)Z")) return "eq";
        if (m.equals("hashCode()I")) return "hash";
        if (h.name().equals("clone")) return "clone";
        if (h.name().equals("compareTo") || h.name().equals("compare")) return "compare";
        if (h.name().equals("iterator") || h.name().equals("hasNext") || h.name().equals("next") || h.name().equals("forEach")
                || h.name().equals("spliterator") || h.name().equals("toArray") || h.name().equals("size") || h.name().equals("get")
                || h.name().equals("entrySet") || h.name().equals("listIterator") || h.name().equals("contains")) return "iterate";
        if (h.name().equals("run") || h.name().equals("call") || h.name().equals("accept") || h.name().equals("apply")
                || h.name().equals("test")) return "callback";
        if (h.name().startsWith("read") || h.name().startsWith("write") || h.name().equals("append") || h.name().equals("flush")
                || h.name().equals("skip") || h.name().equals("available") || h.name().equals("transferTo")) return "io";
        if (h.name().equals("close")) return "drop";
        if (h.name().equals("writeReplace") || h.name().equals("writeExternal")) return "io";
        return "other";
    }
    static boolean bAll(String k) { return !(k.equals("format") || k.equals("eq") || k.equals("hash") || k.equals("clone")); }

    /** Count (and, under a mode, disclose) every hook of a recognised site at a call in {@code id}. */
    static void site(AnalysisContext c, String id, MethodInsnNode min, JdkSites.Entry e, Frame<Interp.ProvValue> rf) {
        if (MODE == null && !COUNT) return;
        for (JdkSites.Hook h : e.hooks()) {
            String k = klass(h);
            String t;
            if (h.slot() == JdkSites.THIS) {
                if (min.getOpcode() == Opcodes.INVOKESTATIC || min.name.equals("<init>")) continue;
                Interp.ProvValue r = rf == null ? null : Candor.receiverProv(rf, min);
                t = r != null && r.declType != null ? r.declType : min.owner;
            } else {
                Interp.ProvValue a = rf == null ? null : Candor.callArg(rf, min, h.slot());
                t = a == null ? null : a.declType;
                if (t != null && h.elem()) t = t.startsWith("[L") ? t.substring(2, t.length() - 1) : null;
            }
            String state;
            if (t == null || t.equals("java/lang/Object")) state = "untyped";
            else if (JdkSites.isJdk(t) && (h.slot() == JdkSites.THIS || c.subtypeIndex.getOrDefault(t, List.of()).isEmpty())
                    && !CallTargets.outsideScan(c, t)) state = "jdk-only";   // no project/dependency type can run here
            else {
                List<String> local = Cha.chaWithReentry(t, h.name(), h.desc());
                state = Cha.inBound(local, t) ? "resolved" : "pastbound";
            }
            if (COUNT) System.err.println("SITEFB\t" + id + "\t" + min.owner + "." + min.name + min.desc + "\t" + h.slot()
                    + (h.elem() ? "[]" : "") + "\t" + h.member() + "\t" + k + "\t" + state);
            boolean unresolved = state.equals("untyped") || state.equals("pastbound");
            if (!unresolved || MODE == null) continue;
            if (MODE.equals("B") && !bAll(k)) continue;
            c.viaCross.computeIfAbsent(id, x -> EffectSet.empty()).add(Effect.UNKNOWN);
            c.unknownWhy.computeIfAbsent(id, x -> new TreeSet<>())
                    .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, min.owner.replace('/', '.') + "." + h.name()));
        }
    }
}
