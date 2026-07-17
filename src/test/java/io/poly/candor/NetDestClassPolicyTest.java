package io.poly.candor;

import static io.poly.candor.AnalysisState.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.EffectSet;
import io.poly.candor.model.PolicyRule;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Reference implementation of the `Net` destination-class security gate (NET-DESTINATION-CLASS-DESIGN.md):
 * `deny Net[unknown-host]` denies Net to a host candor cannot positively identify as telemetry/partner,
 * tolerating the asserted-safe classes; bare `deny Net` stays all-destinations. Classifier + parser +
 * fail-closed evaluation. Mirrors {@link ReasonScopedPolicyTest} for the reason-scoped Unknown gate.
 */
class NetDestClassPolicyTest {

    private static Path policy(Path dir, String body) throws Exception {
        Path p = dir.resolve("arch.policy");
        Files.writeString(p, body);
        return p;
    }

    /** A fn that performs Net to the given resolved host literals. */
    private void seedNet(String fn, String... hosts) {
        ctx().hostsDirect.computeIfAbsent(fn, k -> new TreeSet<>()).addAll(List.of(hosts));
    }

    @Test void classifierMapsHostsToDestinationClasses() {
        assertEquals("known-telemetry", Literals.netDestClass("sentry.io", Set.of()));
        assertEquals("known-telemetry", Literals.netDestClass("us.i.posthog.com", Set.of())); // ⟨0.20.1⟩ corpus-grown
        assertEquals("known-telemetry", Literals.netDestClass("o123.ingest.sentry.io", Set.of()), "subdomain-aware");
        assertEquals("unknown-host", Literals.netDestClass("evil.example.com", Set.of()));
        assertEquals("unknown-host", Literals.netDestClass(null, Set.of()), "unresolved never fabricated onto a safe class");
        assertEquals("known-partner", Literals.netDestClass("api.stripe.com", Set.of("api.stripe.com")), "config-declared partner");
        assertEquals("unknown-host", Literals.netDestClass("api.stripe.com", Set.of()), "partner is config-only — undeclared ⇒ unknown");
    }

    @Test void parsesTheDestinationClassFilter(@TempDir Path dir) throws Exception {
        Candor.resetState();
        Policy.parsePolicy(policy(dir, "deny Net[unknown-host,known-telemetry] dom\n").toString());
        PolicyRule.Deny d = ctx().denyRules.get(0);
        assertEquals(Set.of("unknown-host", "known-telemetry"), d.netClasses());
        assertTrue(d.effects().toNames().contains("Net"), "the rule still denies Net");
    }

    @Test void bareNetAndStarMeanAllDestinations(@TempDir Path dir) throws Exception {
        Candor.resetState();
        Policy.parsePolicy(policy(dir, "deny Net dom\n").toString());
        assertEquals(Set.of(), ctx().denyRules.get(0).netClasses(), "bare Net ⇒ empty filter (all)");
        Candor.resetState();
        Policy.parsePolicy(policy(dir, "deny Net[*] dom2\n").toString());
        assertEquals(Set.of(), ctx().denyRules.get(0).netClasses(), "Net[*] ⇒ empty filter (all)");
    }

    @Test void gateFiresOnUnknownHostToleratesAssertedSafe(@TempDir Path dir) throws Exception {
        String tel = "d.T.telemetry", exfil = "d.E.exfil";
        Map<String, EffectSet> inferred = Map.of(
                tel, EffectSet.ofNames(List.of("Net")),
                exfil, EffectSet.ofNames(List.of("Net")));

        Candor.resetState();
        seedNet(tel, "sentry.io");
        seedNet(exfil, "evil.example.com");
        assertEquals(1, Policy.checkPolicy(inferred, policy(dir, "deny Net[unknown-host]\n").toString()),
                "deny Net[unknown-host] fires on the exfil host only, tolerating the telemetry host");
    }

    /** Fail-closed: a Net with NO visible host (a runtime-computed endpoint) is unknown-host, never guessed safe. */
    @Test void runtimeHostFailsClosedToUnknownHost(@TempDir Path dir) throws Exception {
        String fn = "d.R.runtime";
        Map<String, EffectSet> inferred = Map.of(fn, EffectSet.ofNames(List.of("Net")));
        Candor.resetState(); // Net present, hostsDirect empty ⇒ unknown-host
        assertEquals(1, Policy.checkPolicy(inferred, policy(dir, "deny Net[unknown-host]\n").toString()),
                "a Net with no resolvable host must fail closed to unknown-host");
    }

    /** Fail-closed: a masked surface (AS-EFF-008) taints an otherwise-telemetry fn to unknown-host. */
    @Test void maskedSurfaceFailsClosedEvenWithVisibleTelemetry(@TempDir Path dir) throws Exception {
        String fn = "d.M.masked";
        Map<String, EffectSet> inferred = Map.of(fn, EffectSet.ofNames(List.of("Net")));
        Candor.resetState();
        seedNet(fn, "sentry.io"); // a visible telemetry host…
        ctx().surfaceIncomplete.computeIfAbsent(fn, k -> new TreeSet<>()).add("Net"); // …but the surface is masked
        assertEquals(1, Policy.checkPolicy(inferred, policy(dir, "deny Net[unknown-host]\n").toString()),
                "a benign visible host must not certify a fn that also reaches an invisible endpoint");
    }

    @Test void configPartnerIsToleratedByTheSecurityGate(@TempDir Path dir) throws Exception {
        String fn = "d.P.partner";
        Map<String, EffectSet> inferred = Map.of(fn, EffectSet.ofNames(List.of("Net")));
        Candor.resetState();
        seedNet(fn, "api.stripe.com");
        ctx().netPartners.add("api.stripe.com");
        assertEquals(0, Policy.checkPolicy(inferred, policy(dir, "deny Net[unknown-host]\n").toString()),
                "a config-declared net-partner is known-partner ⇒ tolerated by deny Net[unknown-host]");
    }

    /** The destination class travels the call graph the same way the Net effect does. */
    @Test void destinationClassPropagatesTransitivelyToCallers(@TempDir Path dir) throws Exception {
        String caller = "d.C.entry", callee = "d.E.exfil";
        Map<String, EffectSet> inferred = Map.of(
                caller, EffectSet.ofNames(List.of("Net")),
                callee, EffectSet.ofNames(List.of("Net")));
        Candor.resetState();
        seedNet(callee, "evil.example.com");
        ctx().edges.computeIfAbsent(caller, k -> new java.util.HashSet<>()).add(callee);
        assertEquals(2, Policy.checkPolicy(inferred, policy(dir, "deny Net[unknown-host]\n").toString()),
                "deny Net[unknown-host] must fire on the exfil callee AND the caller that reaches it");
    }
}
