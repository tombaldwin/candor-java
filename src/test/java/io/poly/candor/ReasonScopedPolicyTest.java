package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.EffectSet;
import io.poly.candor.model.PolicyRule;
import io.poly.candor.model.ReasonClass;
import io.poly.candor.model.UnknownReason;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Phase-1 reference implementation of reason-scoped `Unknown` policies (REASON-SCOPED-UNKNOWN-DESIGN.md):
 * `deny E Unknown[class…]` fires its Unknown part only for a matching reason-class; bare `deny E Unknown`
 * stays `Unknown[*]` (any reason). Parser + evaluation.
 */
class ReasonScopedPolicyTest {

    @BeforeEach void fresh() { Candor.resetState(); }

    private static Path policy(@TempDir Path dir, String body) throws Exception {
        Path p = dir.resolve("arch.policy");
        Files.writeString(p, body);
        return p;
    }

    @Test void parsesTheReasonClassFilter(@TempDir Path dir) throws Exception {
        Policy.parsePolicy(policy(dir, "deny Net Unknown[dispatch,indirect] dom\n").toString());
        PolicyRule.Deny d = ctx().denyRules.get(0);
        assertEquals(Set.of(ReasonClass.DISPATCH, ReasonClass.INDIRECT), d.unknownClasses());
        assertTrue(d.effects().toNames().contains("Unknown"), "the rule still denies Unknown");
    }

    @Test void bareUnknownAndStarMeanAllClasses(@TempDir Path dir) throws Exception {
        Policy.parsePolicy(policy(dir, "deny Net Unknown dom\n").toString());
        assertEquals(Set.of(), ctx().denyRules.get(0).unknownClasses(), "bare Unknown ⇒ empty filter (all)");
        Candor.resetState();
        Policy.parsePolicy(policy(dir, "deny Net Unknown[*] dom2\n").toString());
        assertEquals(Set.of(), ctx().denyRules.get(0).unknownClasses(), "Unknown[*] ⇒ empty filter (all)");
    }

    /** A fn whose ONLY effect is Unknown, via a DISPATCH reason. */
    private void seedDispatchUnknown(String fn) {
        ctx().unknownWhy.computeIfAbsent(fn, k -> new TreeSet<>())
                .add(UnknownReason.of(UnknownReason.Kind.DISPATCH, "some.Iface.m"));
    }

    @Test void reasonScopedGateFiresOnMatchToleratesMismatch(@TempDir Path dir) throws Exception {
        String fn = "dom.Svc.run";
        Map<String, EffectSet> inferred = Map.of(fn, EffectSet.ofNames(List.of("Unknown")));

        // matching class → fires
        Candor.resetState(); seedDispatchUnknown(fn);
        assertEquals(1, Policy.checkPolicy(inferred, policy(dir, "deny Net Unknown[dispatch]\n").toString()),
                "deny …Unknown[dispatch] must fire on a dispatch-class Unknown");

        // non-matching class → tolerated (no violation)
        Candor.resetState(); seedDispatchUnknown(fn);
        assertEquals(0, Policy.checkPolicy(inferred, policy(dir, "deny Net Unknown[reflect]\n").toString()),
                "deny …Unknown[reflect] must TOLERATE a dispatch-class Unknown");

        // bare Unknown[*] → fires regardless of class (unchanged semantics)
        Candor.resetState(); seedDispatchUnknown(fn);
        assertEquals(1, Policy.checkPolicy(inferred, policy(dir, "deny Net Unknown\n").toString()),
                "bare deny …Unknown must fire on any Unknown");
    }

    @Test void dynamicAliasExpandsToAllGenuineClasses(@TempDir Path dir) throws Exception {
        Policy.parsePolicy(policy(dir, "deny Net Unknown[dynamic] dom\n").toString());
        assertEquals(
                Set.of(ReasonClass.REFLECT, ReasonClass.DISPATCH, ReasonClass.INDIRECT, ReasonClass.NATIVE, ReasonClass.UNRESOLVED),
                ctx().denyRules.get(0).unknownClasses(),
                "`dynamic` = every genuine class incl. unresolved, excl. setup");
        // and it fires on a dispatch-class Unknown (dispatch ∈ dynamic)
        String fn = "dom.Svc.run";
        Candor.resetState(); seedDispatchUnknown(fn);
        assertEquals(1, Policy.checkPolicy(Map.of(fn, EffectSet.ofNames(List.of("Unknown"))),
                policy(dir, "deny Net Unknown[dynamic]\n").toString()));
    }

    /** The reason CLASS must travel the call graph the same way the Unknown EFFECT does: a caller that
     *  inherits Unknown from a reflect-caused callee is a reflect-class Unknown, even though the `reflect:*`
     *  reason was emitted directly on the callee. Regression for the transitive-reason under-gating gap. */
    @Test void reasonClassPropagatesTransitivelyToCallers(@TempDir Path dir) throws Exception {
        String caller = "dom.Caller.entry", callee = "dom.Svc.reflecty";
        // caller inherits Unknown transitively; only the callee carries the reflect reason.
        Map<String, EffectSet> inferred = Map.of(
                caller, EffectSet.ofNames(List.of("Unknown")),
                callee, EffectSet.ofNames(List.of("Unknown")));

        Candor.resetState();
        ctx().unknownWhy.computeIfAbsent(callee, k -> new TreeSet<>())
                .add(UnknownReason.of(UnknownReason.Kind.REFLECT, "java.lang.reflect.Method.invoke"));
        ctx().edges.computeIfAbsent(caller, k -> new java.util.HashSet<>()).add(callee);

        assertEquals(2, Policy.checkPolicy(inferred, policy(dir, "deny Net Unknown[reflect]\n").toString()),
                "deny …Unknown[reflect] must fire on BOTH the reflect callee and the caller that inherits its Unknown");
    }

    @Test void unknownWithNoRecordedReasonIsUnresolvedConservatively(@TempDir Path dir) throws Exception {
        String fn = "dom.Svc.opaque";
        Map<String, EffectSet> inferred = Map.of(fn, EffectSet.ofNames(List.of("Unknown")));
        // no ctx().unknownWhy entry for fn → treated as `unresolved`
        Candor.resetState();
        assertEquals(1, Policy.checkPolicy(inferred, policy(dir, "deny Net Unknown[unresolved]\n").toString()),
                "an Unknown with no recorded reason must fall under `unresolved`");
        Candor.resetState();
        assertEquals(0, Policy.checkPolicy(inferred, policy(dir, "deny Net Unknown[reflect]\n").toString()),
                "…and must NOT match a specific class it wasn't tagged with");
    }
}
