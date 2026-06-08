package candor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

/**
 * candor-java (prototype) — a candor-spec implementation for the JVM, via ASM bytecode.
 *
 * Resolves each call to its concrete target, classifies it, records per-method DIRECT effects +
 * call edges, then propagates to a transitive fixpoint. See https://github.com/tombaldwin/candor-spec.
 *
 * SPRING-AWARE: Spring hides effects in framework-woven/generated code (proxies for @Transactional,
 * synthesized Spring Data repositories) and breaks the call graph (reflective ingress). Pure bytecode
 * tracing misses all of it. So we read Spring's DECLARATIONS — annotations and template/repository
 * types — as effect sources. The framework's magic becomes the signal.
 *
 * TRUST CONTRACT (SPEC §4): what candor can't see is reported as `Unknown`, never assumed pure —
 * reflection / dynamic invocation, a `native` (JNI) body, and dispatch over a project interface/abstract
 * with no visible impl. CHA resolves interface/virtual dispatch over project types; constructors,
 * static initializers (`<clinit>`, via class-load trigger edges), and lambdas/method-refs all propagate
 * their effects. Conformance (CANDOR_STRICT) treats a bean's injected dependencies as its capabilities.
 * Residual gap (PRINCIPLES #7): dispatch over unrecognised non-project types is assumed pure (else
 * every `list.add()` floods) — known-effectful libraries are caught by the classifier.
 */
public class Candor {
    static final Map<String, TreeSet<String>> direct = new HashMap<>();
    static final Map<String, Set<String>> edges = new HashMap<>();
    static final Map<String, String> loc = new HashMap<>();
    static final Map<String, String> hashOf = new HashMap<>();           // fn -> stable method-ref hash (owner.name+desc)
    static final Map<String, TreeSet<String>> viaCross = new HashMap<>();// fn -> effects inherited from a dependency report
    static final Map<String, List<String>> crossDeps = new HashMap<>();  // method-ref hash -> effects (from CANDOR_DEPS)
    static final Map<String, TreeSet<String>> fsDirect = new HashMap<>();// fn -> Fs read/write kind performed directly
    static final String FS_UNKNOWN = "?";   // Fs reached with no recorded kind (cross-jar) -> make no read/write claim
    static final Set<String> entryPoints = new HashSet<>(); // framework-invoked methods
    static final Set<String> projectClasses = new HashSet<>();
    static final Set<String> repoTypes = new HashSet<>();    // Spring Data repository interfaces (internal names)
    static final Set<String> feignTypes = new HashSet<>();   // @FeignClient interfaces (internal names)
    static List<ClassNode> ALL = List.of();                  // all loaded classes (for CHA)
    static final Map<String, ClassNode> byName = new HashMap<>();      // internal name -> node
    static final Map<String, Set<String>> transSupersCache = new HashMap<>();
    static final Set<String> classesWithClinit = new HashSet<>(); // project classes with a `<clinit>`

    // --- Spring markers (internal names / annotation-desc substrings) ---
    static final Set<String> REPO_MARKERS = Set.of(
            "org/springframework/data/repository/Repository",
            "org/springframework/data/repository/CrudRepository",
            "org/springframework/data/repository/ListCrudRepository",
            "org/springframework/data/repository/PagingAndSortingRepository",
            "org/springframework/data/jpa/repository/JpaRepository");
    static final String TX = "springframework/transaction/annotation/Transactional";
    static final String SCHEDULED = "springframework/scheduling/annotation/Scheduled";
    static final String FEIGN = "openfeign/FeignClient";
    // Ambient authorities (for CANDOR_NO_AMBIENT). Log/Unknown are not authorities.
    static final Set<String> AMBIENT = Set.of("Net", "Fs", "Db", "Exec", "Env", "Clock", "Rand");
    // The effect vocabulary candor-java emits (used to split a `deny <Effect…> [scope]` rule's effects
    // from its trailing scope token).
    static final Set<String> KNOWN_EFFECTS = Set.of("Net", "Fs", "Db", "Exec", "Env", "Clock", "Rand", "Log", "Ipc");

    // CANDOR_POLICY rules (architecture-as-code, candor-spec §5). `deny`/`pure` = AS-EFF-006 (what a
    // layer may do); `allow … in …` = AS-EFF-008 (which endpoints); `forbid A -> B` = AS-EFF-009 (who
    // a layer may depend on).
    static final List<DenyRule> denyRules = new ArrayList<>();
    static final List<AllowRule> allowRules = new ArrayList<>();
    static final List<ForbidRule> forbidRules = new ArrayList<>();
    static final Map<String, TreeSet<String>> hostsDirect = new HashMap<>(); // fn -> literal Net endpoints

    /** A `deny <Effect…> [scope]` or `pure <scope>` rule. `effects` empty ⇒ a `pure` rule (ANY effect is
     *  forbidden). `scope` empty ⇒ the whole project. */
    static class DenyRule { TreeSet<String> effects = new TreeSet<>(); String scope = ""; String src; }
    /** An `allow <Effect> [in <scope>] <value…>` rule: a method in scope performing that effect may reach
     *  ONLY the listed values (Net hosts today). `scope` empty ⇒ whole project. */
    static class AllowRule { String effect; String scope = ""; TreeSet<String> values = new TreeSet<>(); String src; }
    /** A `forbid <A> -> <B>` rule: a method in scope A must not transitively reach into scope B. */
    static class ForbidRule { String from, to; }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: candor <dir-or-jar-of-classes> [--json <file>]");
            System.err.println("       candor <show|where|callers|map|diff> <report.json> [arg]");
            System.exit(2);
        }
        // Read-only queries over a written report (no re-analysis) — the sibling of candor-query.
        if (Query.COMMANDS.contains(args[0])) {
            System.exit(Query.run(args));
        }
        String jsonOut = null;
        for (int i = 1; i + 1 < args.length; i++) if (args[i].equals("--json")) jsonOut = args[i + 1];

        List<ClassNode> classes = load(Path.of(args[0]));
        ALL = classes;
        for (ClassNode cn : classes) {
            projectClasses.add(cn.name);
            byName.put(cn.name, cn);
            for (MethodNode mn : cn.methods) if (mn.name.equals("<clinit>")) classesWithClinit.add(cn.name);
        }
        computeSpringTypes(classes);
        // Cross-jar inheritance (candor-spec §2): load dependency reports named by CANDOR_DEPS BEFORE
        // analyze, so a call into an already-analyzed dependency inherits its effects (vs assumed-pure).
        loadCrossDeps(System.getenv("CANDOR_DEPS"), provenance()[0]);
        for (ClassNode cn : classes) analyze(cn);

        Map<String, TreeSet<String>> inferred = fixpoint();

        // JSON output is orthogonal — write first so `--json` can snapshot a baseline.
        if (jsonOut != null) writeJson(inferred, jsonOut);

        // Modes: CANDOR_STRICT (conformance via DI), CANDOR_BASELINE (regression guard),
        // CANDOR_NO_AMBIENT (enforcement).
        String strict = System.getenv("CANDOR_STRICT");
        String baseline = System.getenv("CANDOR_BASELINE");
        String noAmbient = System.getenv("CANDOR_NO_AMBIENT");
        String policy = System.getenv("CANDOR_POLICY");
        boolean enforce = baseline != null || noAmbient != null || strict != null || policy != null;

        if (!enforce) {
            System.out.println("candor-java — effect audit (Spring-aware; Unknown for reflection/dispatch)\n");
            inferred.entrySet().stream()
                    .filter(e -> !e.getValue().isEmpty())
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> {
                        var d = direct.getOrDefault(e.getKey(), new TreeSet<>());
                        String set = e.getValue().stream()
                                .map(x -> d.contains(x) ? x : x + "*")
                                .collect(Collectors.joining(", "));
                        String tag = entryPoints.contains(e.getKey()) ? "  [entry]" : "";
                        System.out.printf("  %-52s { %s }%s%n", e.getKey(), set, tag);
                    });
            System.out.println("\n(* = via callee, [entry] = framework-invoked entry point)");
            return;
        }

        int violations = 0;
        if (strict != null) violations += checkConformance(inferred, strict);
        if (noAmbient != null) violations += checkNoAmbient(inferred, noAmbient);
        if (baseline != null) violations += checkBaseline(inferred, baseline);
        if (policy != null) violations += checkPolicy(inferred, policy);
        if (violations == 0) System.out.println("candor-java: no violations");
        if (violations > 0) System.exit(1); // fail CI
    }

    /**
     * Conformance via dependency injection: a class's fields are the capabilities it holds, so its
     * effects must be covered by what those collaborators provide. An effect performed beyond them
     * means reaching for ambient authority instead of receiving it (AS-EFF-001). This is candor's
     * capability-token model in Java's idiom — "a bean's signature (its dependencies) tells you its
     * effect surface."
     */
    static int checkConformance(Map<String, TreeSet<String>> inferred, String scope) {
        // performed(class) = union of inferred over the class's own methods.
        Map<String, TreeSet<String>> performed = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> p = performed.computeIfAbsent(dc, k -> new TreeSet<>());
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                var inf = inferred.get(dc + "." + mn.name);
                if (inf != null) p.addAll(inf);
            }
        }
        int v = 0;
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            if (!inScope(scope, dc)) continue;
            TreeSet<String> declared = new TreeSet<>();
            if (cn.fields != null)
                for (FieldNode f : cn.fields) {
                    String t = fieldTypeInternal(f.desc);
                    if (t != null) declared.addAll(typeEffects(t, performed));
                }
            TreeSet<String> perf = performed.getOrDefault(dc, new TreeSet<>());
            boolean hasUnknown = perf.contains("Unknown");
            List<String> undeclared = perf.stream()
                    .filter(x -> !x.equals("Unknown") && !declared.contains(x)).sorted().collect(Collectors.toList());
            List<String> unused = declared.stream()
                    .filter(x -> !perf.contains(x)).sorted().collect(Collectors.toList());
            if (!undeclared.isEmpty()) {
                String have = declared.isEmpty() ? "no injected capability"
                        : "only { " + String.join(", ", declared) + " }";
                System.out.printf("[AS-EFF-001] class `%s` performs { %s } but holds %s; "
                        + "inject a collaborator that provides it (don't reach for ambient authority)%n",
                        dc, String.join(", ", undeclared), have);
                v++;
            }
            if (hasUnknown) {
                System.out.printf("[AS-EFF-003] class `%s` makes calls candor cannot resolve "
                        + "(reflection / unresolved dispatch); effect set not provably complete%n", dc);
                v++;
            }
            if (!unused.isEmpty()) {
                System.out.printf("[AS-EFF-002] class `%s` injects { %s } but never uses it%n",
                        dc, String.join(", ", unused));
                v++;
            }
        }
        return v;
    }

    /** Effects a field of type `internal` can supply (Spring repo/template, or a project collaborator). */
    static Set<String> typeEffects(String internal, Map<String, TreeSet<String>> performed) {
        if (repoTypes.contains(internal)) return Set.of("Db");
        if (feignTypes.contains(internal)) return Set.of("Net");
        String dotted = internal.replace('/', '.');
        Set<String> lib = classifyType(dotted);
        if (!lib.isEmpty()) return lib;
        if (byName.containsKey(internal)) return performed.getOrDefault(dotted, new TreeSet<>());
        return Set.of();
    }

    /** Type-level classification of a collaborator (mirrors the call-level classify, by owner type). */
    static Set<String> classifyType(String dotted) {
        if (dotted.equals("org.springframework.web.client.RestTemplate")
                || dotted.equals("org.springframework.web.client.RestClient")
                || dotted.startsWith("org.springframework.web.reactive.function.client.")
                || dotted.equals("org.springframework.jms.core.JmsTemplate")
                || dotted.equals("org.springframework.kafka.core.KafkaTemplate"))
            return Set.of("Net");
        if (dotted.equals("org.springframework.jdbc.core.JdbcTemplate")
                || dotted.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                || dotted.equals("jakarta.persistence.EntityManager")
                || dotted.equals("javax.persistence.EntityManager"))
            return Set.of("Db");
        return Set.of();
    }

    /** Object type internal name from a field descriptor (`Lcom/x/Foo;` -> `com/x/Foo`); null if primitive. */
    static String fieldTypeInternal(String desc) {
        int l = desc.indexOf('L');
        if (l >= 0 && desc.endsWith(";")) return desc.substring(l + 1, desc.length() - 1);
        return null;
    }

    /** AS-EFF-004: flag direct use of ambient authority (route it through an injected collaborator). */
    static int checkNoAmbient(Map<String, TreeSet<String>> inferred, String scope) {
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            if (!inScope(scope, e.getKey())) continue;
            List<String> ambient = direct.getOrDefault(e.getKey(), new TreeSet<>()).stream()
                    .filter(AMBIENT::contains).sorted().collect(Collectors.toList());
            if (!ambient.isEmpty()) {
                System.out.printf("[AS-EFF-004] `%s` uses ambient authority { %s } directly; "
                        + "route it through an injected collaborator / capability%n",
                        e.getKey(), String.join(", ", ambient));
                v++;
            }
        }
        return v;
    }

    /** AS-EFF-005: flag a function that gained an effect versus a saved baseline report. */
    static int checkBaseline(Map<String, TreeSet<String>> inferred, String path) {
        Map<String, Set<String>> base = loadBaseline(path);
        if (base == null) {
            System.err.println("candor-java: CANDOR_BASELINE set but " + path
                    + " could not be loaded — the regression guard is NOT active");
            return 0;
        }
        int v = 0;
        for (var e : new TreeMap<>(inferred).entrySet()) {
            Set<String> prior = base.get(e.getKey());
            if (prior == null) continue; // new function — reviewed as new code, not a regression
            List<String> gained = e.getValue().stream()
                    .filter(x -> !prior.contains(x)).sorted().collect(Collectors.toList());
            if (!gained.isEmpty()) {
                System.out.printf("[AS-EFF-005] `%s` gained effect { %s } not present in the baseline%n",
                        e.getKey(), String.join(", ", gained));
                v++;
            }
        }
        return v;
    }

    /** CANDOR_POLICY (candor-spec §5): architecture-as-code. Enforces two boundary kinds, both
     *  TRANSITIVELY (so they catch what a local diff hides):
     *   - AS-EFF-006 `deny <Effect…> [scope]` / `pure <scope>` — WHAT a layer may do.
     *   - AS-EFF-009 `forbid <A> -> <B>` — WHO a layer may depend on (reachability over the call graph).
     *  A set-but-unreadable policy is LOUD (not silently passing). (AS-EFF-008 literal allowlists —
     *  `allow <Effect> in <scope> <value>` — are parsed-but-skipped for now; they need per-call literal
     *  extraction, the next rung.) */
    static int checkPolicy(Map<String, TreeSet<String>> inferred, String path) {
        if (!parsePolicy(path)) {
            System.err.println("candor-java: CANDOR_POLICY=" + path
                    + " could not be read; policy NOT enforced");
            return 0;
        }
        int v = 0;
        // AS-EFF-006: a method in scope must not perform (transitively) a denied effect.
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            for (DenyRule r : denyRules) {
                if (!scopeMatches(fn, r.scope)) continue;
                List<String> bad = r.effects.isEmpty()
                        ? e.getValue().stream().filter(x -> !x.equals("Unknown")).sorted().collect(Collectors.toList())
                        : e.getValue().stream().filter(r.effects::contains).sorted().collect(Collectors.toList());
                if (!bad.isEmpty()) {
                    System.out.printf("[AS-EFF-006] `%s` performs { %s }, forbidden by policy%s: `%s`%n",
                            fn, String.join(", ", bad),
                            r.scope.isEmpty() ? "" : " (scope `" + r.scope + "`)", r.src);
                    v++;
                }
            }
        }
        // AS-EFF-008: a method in an allow-listed scope must reach ONLY the listed Net endpoints. Certifies
        // the VISIBLE host surface (literal endpoints, propagated transitively); a method with Net but no
        // visible host can't be certified and isn't flagged (the documented limit). Allowed values are
        // UNIONed across every matching `allow Net …` rule, then reached hosts must be a subset.
        Map<String, TreeSet<String>> hostsAcc = hostsFixpoint();
        for (var e : new TreeMap<>(inferred).entrySet()) {
            String fn = e.getKey();
            if (!e.getValue().contains("Net")) continue;
            Set<String> allowed = null; // null ⇒ no `allow Net` rule covers this method → not checked
            String scopeLabel = "";
            for (AllowRule r : allowRules) {
                if (!"Net".equals(r.effect) || !scopeMatches(fn, r.scope)) continue;
                if (allowed == null) { allowed = new HashSet<>(); scopeLabel = r.scope; }
                for (String val : r.values) allowed.add(hostPart(val));
            }
            if (allowed == null) continue;
            Set<String> finalAllowed = allowed;
            List<String> bad = hostsAcc.getOrDefault(fn, new TreeSet<>()).stream()
                    .filter(h -> !finalAllowed.contains(hostPart(h))).sorted().collect(Collectors.toList());
            if (!bad.isEmpty()) {
                System.out.printf("[AS-EFF-008] `%s` reaches { %s } outside the allowlist, forbidden by "
                        + "policy%s: `allow Net … %s`%n", fn, String.join(", ", bad),
                        scopeLabel.isEmpty() ? "" : " (scope `" + scopeLabel + "`)",
                        String.join(" ", new TreeSet<>(allowed)));
                v++;
            }
        }
        // AS-EFF-009: a method in scope A must not transitively reach into scope B (over the call graph).
        for (ForbidRule r : forbidRules) {
            for (String fn : new TreeSet<>(edges.keySet())) {
                if (!scopeMatches(fn, r.from)) continue;
                String hit = reachesScope(fn, r.to);
                if (hit != null) {
                    System.out.printf("[AS-EFF-009] `%s` reaches into a forbidden layer (via `%s`), "
                            + "violating policy: `forbid %s -> %s`%n", fn, hit, r.from, r.to);
                    v++;
                }
            }
        }
        return v;
    }

    /** Parse a CANDOR_POLICY file into deny/forbid rules. One rule per line; `#` comments + blanks
     *  ignored. Returns false if the file can't be read (so the caller can fail loud). */
    static boolean parsePolicy(String path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(path));
        } catch (IOException e) {
            return false;
        }
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] t = line.split("\\s+");
            switch (t[0]) {
                case "deny": {
                    DenyRule r = new DenyRule();
                    r.src = line;
                    for (int i = 1; i < t.length; i++) {
                        if (KNOWN_EFFECTS.contains(t[i])) r.effects.add(t[i]);
                        else r.scope = t[i]; // a trailing non-effect token is the scope
                    }
                    denyRules.add(r);
                    break;
                }
                case "pure": {
                    DenyRule r = new DenyRule(); // empty effects = ANY effect forbidden
                    r.src = line;
                    if (t.length > 1) r.scope = t[1];
                    denyRules.add(r);
                    break;
                }
                case "forbid": {
                    int arrow = line.indexOf("->");
                    if (arrow > "forbid".length()) {
                        ForbidRule r = new ForbidRule();
                        r.from = line.substring("forbid".length(), arrow).trim();
                        r.to = line.substring(arrow + 2).trim();
                        if (!r.from.isEmpty() && !r.to.isEmpty()) forbidRules.add(r);
                    }
                    break;
                }
                case "allow": {
                    // allow <Effect> [in <scope>] <value…>
                    if (t.length < 3) break;
                    AllowRule r = new AllowRule();
                    r.src = line;
                    r.effect = t[1];
                    int vi = 2;
                    if (t.length > 3 && t[2].equals("in")) { r.scope = t[3]; vi = 4; }
                    for (int i = vi; i < t.length; i++) r.values.add(t[i]);
                    if (!r.values.isEmpty()) allowRules.add(r);
                    break;
                }
                default:
                    break;
            }
        }
        return true;
    }

    /** A policy scope matches a method by dotted SEGMENT (so `domain` matches `app.domain.Svc.handle`
     *  and the `domain_logic` package, but not `subdomain`). Mirrors the Rust impl's `scope_matches`:
     *  a contiguous run of segments — intermediate segments exact, the LAST a prefix. Empty scope ⇒
     *  whole project (matches everything). */
    static boolean scopeMatches(String name, String scope) {
        if (scope.isEmpty()) return true;
        String[] segs = name.split("\\.");
        String[] parts = scope.split("\\.");
        if (parts.length == 0 || parts.length > segs.length) return false;
        String last = parts[parts.length - 1];
        for (int i = 0; i + parts.length <= segs.length; i++) {
            boolean ok = true;
            for (int j = 0; j < parts.length - 1; j++)
                if (!segs[i + j].equals(parts[j])) { ok = false; break; }
            if (ok && segs[i + parts.length - 1].startsWith(last)) return true;
        }
        return false;
    }

    /** Forward reachability over the project call graph: the first method `start` transitively reaches
     *  whose name matches `scope` (seeded from `start`'s direct callees, so `start` itself isn't a hit),
     *  or null. Used for AS-EFF-009 layering. */
    static String reachesScope(String start, String scope) {
        Deque<String> stack = new ArrayDeque<>(edges.getOrDefault(start, Set.of()));
        Set<String> seen = new HashSet<>();
        while (!stack.isEmpty()) {
            String n = stack.pop();
            if (!seen.add(n)) continue;
            if (scopeMatches(n, scope)) return n;
            for (String c : edges.getOrDefault(n, Set.of())) if (!seen.contains(c)) stack.push(c);
        }
        return null;
    }

    /** The network endpoint a string literal names — `host[:port]`, scheme/path/userinfo stripped — or
     *  null if the string isn't UNAMBIGUOUSLY an endpoint. Real code is full of dotted strings that are
     *  NOT hosts — property keys (`os.name`), message keys (`terms.agency`), filenames (`page.html`),
     *  format strings (`"status":"`) — so a bare dotted name is rejected: it's indistinguishable from a
     *  property key without seeing the call it feeds. Accepted: a scheme URL (`https://…`), a
     *  `host:port` with a NUMERIC port, or a bare IPv4. The cost is UNDER-extraction (a bare-hostname
     *  `new Socket("api.example.com", 443)` isn't seen) — the sound direction for a visible-surface
     *  allowlist (a missed host can't certify, but never silently PASSES a forbidden one); modern HTTP
     *  clients use full URLs, which are caught. (Validated against a 2257-class Spring app, which had
     *  ~14 false dotted "hosts" under the old loose filter.) */
    static String netHostLiteral(String s) {
        if (s == null || s.isBlank()) return null;
        String h = s.trim();
        int scheme = h.indexOf("://");
        if (scheme >= 0) { // a URL: take the authority, drop path + userinfo
            h = h.substring(scheme + 3);
            int slash = h.indexOf('/'); if (slash >= 0) h = h.substring(0, slash);
            int at = h.lastIndexOf('@'); if (at >= 0) h = h.substring(at + 1);
            return (h.isBlank() || h.contains(" ")) ? null : h;
        }
        if (h.contains(" ") || h.contains("/")) return null;
        int colon = h.indexOf(':');
        if (colon > 0) { // host:port — accept only with a numeric port and a dotted/IP host
            String host = h.substring(0, colon), port = h.substring(colon + 1);
            boolean numericPort = !port.isEmpty() && port.chars().allMatch(Character::isDigit);
            return (numericPort && host.contains(".")) ? h : null;
        }
        return looksLikeIpv4(h) ? h : null; // a bare token: only a literal IPv4 is unambiguous
    }

    /** Whether `h` is a dotted-quad IPv4 literal (`1.2.3.4`) — the one bare (scheme-less, port-less)
     *  form that's unambiguously a network endpoint, not a property/message key. */
    static boolean looksLikeIpv4(String h) {
        String[] p = h.split("\\.", -1);
        if (p.length != 4) return false;
        for (String x : p) {
            if (x.isEmpty() || x.length() > 3 || !x.chars().allMatch(Character::isDigit)) return false;
            if (Integer.parseInt(x) > 255) return false;
        }
        return true;
    }

    /** The bare hostname of an endpoint (port + any residue stripped), so the allowlist matches
     *  port-insensitively: `api.stripe.com:443` is covered by `allow Net … api.stripe.com`. */
    static String hostPart(String h) {
        String x = h;
        int scheme = x.indexOf("://"); if (scheme >= 0) x = x.substring(scheme + 3);
        int slash = x.indexOf('/');    if (slash >= 0)  x = x.substring(0, slash);
        int at = x.lastIndexOf('@');   if (at >= 0)     x = x.substring(at + 1);
        int colon = x.indexOf(':');    if (colon >= 0)  x = x.substring(0, colon);
        return x;
    }

    /** Propagate literal Net endpoints along the SAME call graph as effects (separate set), so a method
     *  that reaches the network only through a callee still sees the callee's endpoints — the scale path
     *  for AS-EFF-008 (the literal often lives in a deep, even cross-layer, callee). */
    static Map<String, TreeSet<String>> hostsFixpoint() {
        Map<String, TreeSet<String>> hosts = new HashMap<>();
        for (var e : hostsDirect.entrySet()) hosts.put(e.getKey(), new TreeSet<>(e.getValue()));
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                TreeSet<String> add = new TreeSet<>();
                for (String c : edges.get(caller)) {
                    var ce = hosts.get(c);
                    if (ce != null) add.addAll(ce);
                }
                if (add.isEmpty()) continue;
                var set = hosts.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                set.addAll(add);
                if (set.size() != before) changed = true;
            }
        }
        return hosts;
    }

    /** Load dependency reports named by CANDOR_DEPS (a path list — space/colon/comma-separated; a
     *  directory is scanned for *.json) into a `method-ref hash -> inferred effects` map, so a call
     *  into an already-analyzed dependency inherits its effects (candor-spec §2). Version-aware trust
     *  (§2.1): effects from a report produced by a DIFFERENT engine version are downgraded to Unknown
     *  rather than silently trusted. Unreadable/legacy-v0.1 (no hash) entries are skipped. */
    static void loadCrossDeps(String spec, String ownVersion) {
        if (spec == null || spec.isBlank()) return;
        for (String tok : spec.split("[\\s:,]+")) {
            if (tok.isBlank()) continue;
            Path p = Path.of(tok);
            List<Path> files = new ArrayList<>();
            try {
                if (Files.isDirectory(p)) {
                    try (var s = Files.walk(p)) {
                        s.filter(f -> f.toString().endsWith(".json")).forEach(files::add);
                    }
                } else if (Files.isRegularFile(p)) {
                    files.add(p);
                }
            } catch (IOException e) {
                continue;
            }
            for (Path f : files) {
                try {
                    JsonElement root = JsonParser.parseString(Files.readString(f));
                    JsonObject obj = root.isJsonObject() ? root.getAsJsonObject() : null;
                    JsonArray fns = obj != null ? obj.getAsJsonArray("functions")
                            : (root.isJsonArray() ? root.getAsJsonArray() : null);
                    if (fns == null) continue;
                    String depVer = obj != null && obj.has("candor") && obj.getAsJsonObject("candor").has("version")
                            ? obj.getAsJsonObject("candor").get("version").getAsString() : null;
                    boolean stale = depVer != null && ownVersion != null && !depVer.equals(ownVersion);
                    for (JsonElement el : fns) {
                        JsonObject m = el.getAsJsonObject();
                        if (!m.has("hash") || m.get("hash").isJsonNull()) continue; // v0.1 / no cross-jar id
                        String h = m.get("hash").getAsString();
                        if (h.isBlank()) continue;
                        List<String> effs = new ArrayList<>();
                        if (stale) {
                            effs.add("Unknown");
                        } else if (m.has("inferred")) {
                            for (JsonElement x : m.getAsJsonArray("inferred")) effs.add(x.getAsString());
                        }
                        if (!effs.isEmpty()) crossDeps.put(h, effs);
                    }
                } catch (Exception ex) {
                    // skip unreadable / unparseable dependency reports (like the Rust impl)
                }
            }
        }
    }

    static class BaseEntry { String fn; List<String> inferred; }

    static Map<String, Set<String>> loadBaseline(String path) {
        try {
            String text = Files.readString(Path.of(path));
            // Accept BOTH the v0.2 self-describing envelope `{ candor, functions:[...] }` and the legacy
            // v0.1 bare array `[...]` — the migration contract (candor-spec §2: readers MUST accept both).
            JsonElement root = JsonParser.parseString(text);
            JsonArray arr = root.isJsonObject()
                    ? root.getAsJsonObject().getAsJsonArray("functions")
                    : (root.isJsonArray() ? root.getAsJsonArray() : null);
            if (arr == null) return null;
            List<BaseEntry> entries = new Gson().fromJson(arr, new TypeToken<List<BaseEntry>>() {}.getType());
            Map<String, Set<String>> m = new HashMap<>();
            for (BaseEntry e : entries) if (e.fn != null) m.put(e.fn, new HashSet<>(e.inferred == null ? List.of() : e.inferred));
            return m;
        } catch (Exception ex) {
            return null;
        }
    }

    static boolean inScope(String var, String name) {
        return var.equals("1") || var.isEmpty() || name.startsWith(var);
    }

    static List<ClassNode> load(Path root) throws IOException {
        List<ClassNode> out = new ArrayList<>();
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".class"))::iterator) {
                ClassNode cn = new ClassNode();
                new ClassReader(Files.readAllBytes(p)).accept(cn, 0);
                out.add(cn);
            }
        }
        return out;
    }

    /** Identify Spring Data repositories (effect: Db) and @FeignClient interfaces (Net). */
    static void computeSpringTypes(List<ClassNode> classes) {
        for (ClassNode cn : classes) if (annoPresent(cn.visibleAnnotations, FEIGN)) feignTypes.add(cn.name);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (ClassNode cn : classes) {
                if (repoTypes.contains(cn.name) || cn.interfaces == null) continue;
                for (String itf : cn.interfaces) {
                    if (REPO_MARKERS.contains(itf) || repoTypes.contains(itf)) {
                        repoTypes.add(cn.name);
                        changed = true;
                        break;
                    }
                }
            }
        }
    }

    static void analyze(ClassNode cn) {
        String dottedClass = cn.name.replace('/', '.');
        boolean classTx = annoPresent(cn.visibleAnnotations, TX);
        for (MethodNode mn : cn.methods) {
            // Constructors (`<init>`) AND static initializers (`<clinit>`) are both analyzed: a `new X()`
            // edges to `X.<init>`, and a class-load trigger (`new`, a static call, a static field access)
            // edges to `X.<clinit>` (see below), so an effectful constructor OR static initializer
            // propagates to its use site instead of being silently pure.
            String id = dottedClass + "." + mn.name;
            var dir = direct.computeIfAbsent(id, k -> new TreeSet<>());
            edges.computeIfAbsent(id, k -> new HashSet<>());
            loc.putIfAbsent(id, cn.sourceFile + ":" + firstLine(mn));
            // Stable, descriptor-bearing cross-jar identity (candor-spec §2 `hash`): the exact ref a
            // call site in a dependent jar uses, so that jar can inherit this method's effects.
            hashOf.putIfAbsent(id, cn.name + "." + mn.name + mn.desc);

            // A `native` method has no bytecode body — its JNI implementation could perform ANY effect,
            // exactly the opacity reflection has. Honest `Unknown`, never silent-pure (SPEC §4); else a
            // call into a project-declared native binding would look like a no-op.
            if ((mn.access & Opcodes.ACC_NATIVE) != 0) dir.add("Unknown");

            // Spring annotations on this method (the effect Spring's proxy/generated code performs).
            if (classTx || annoPresent(mn.visibleAnnotations, TX)) dir.add("Db");
            if (annoPresent(mn.visibleAnnotations, SCHEDULED)
                    || annoPresentAny(mn.visibleAnnotations, MAPPING_OR_LISTENER))
                entryPoints.add(id);

            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode min) {
                    String owner = min.owner.replace('/', '.');
                    String effect = classify(owner, min.name);
                    if (effect != null) dir.add(effect);
                    if ("Fs".equals(effect)) { // non-breaking read/write refinement of Fs
                        List<String> k = fsKind(owner, min.name);
                        if (!k.isEmpty()) fsDirect.computeIfAbsent(id, x -> new TreeSet<>()).addAll(k);
                    }
                    // Calls to a Spring Data repository / Feign client are I/O even though the
                    // callee has no body candor can see (Spring synthesizes the impl at runtime).
                    boolean springTyped = repoTypes.contains(min.owner) || feignTypes.contains(min.owner);
                    if (repoTypes.contains(min.owner)) dir.add("Db");
                    if (feignTypes.contains(min.owner)) dir.add("Net");

                    int op = min.getOpcode();
                    // A static call triggers the owner's class-load → its `<clinit>` runs.
                    if (op == Opcodes.INVOKESTATIC) clinitEdge(id, min.owner);
                    if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKEINTERFACE) {
                        // Class Hierarchy Analysis: dispatch could reach any project subtype's
                        // override — add edges to all of them so their effects propagate.
                        List<String> targets = chaTargets(min.owner, min.name, min.desc);
                        edges.get(id).addAll(targets);
                        // Genuine unresolved dispatch: a PROJECT interface/abstract type with no
                        // visible impl (DI-wired, external, or strategy) → honest Unknown (SPEC §4).
                        if (targets.isEmpty() && effect == null && !springTyped
                                && isProjectIfaceOrAbstract(min.owner))
                            dir.add("Unknown");
                    } else if (projectClasses.contains(min.owner)) {
                        // static / special (super, private, ctor) — the exact target.
                        edges.get(id).add(owner + "." + min.name);
                    }
                    // Cross-jar inheritance (candor-spec §2): a call into a DEPENDENCY analyzed
                    // separately — inherit its recorded effects via the stable method-ref hash. Only
                    // for external, non-built-in, non-Spring calls (project calls trace locally;
                    // reflection is already Unknown via classify).
                    if (effect == null && !springTyped && !projectClasses.contains(min.owner)) {
                        List<String> inh = crossDeps.get(min.owner + "." + min.name + min.desc);
                        if (inh != null) viaCross.computeIfAbsent(id, k -> new TreeSet<>()).addAll(inh);
                    }
                } else if (insn instanceof TypeInsnNode tin && tin.getOpcode() == Opcodes.NEW) {
                    // `new C` triggers C's class-load → its `<clinit>` runs (the `<init>` edge is added
                    // separately by the INVOKESPECIAL above).
                    clinitEdge(id, tin.desc);
                } else if (insn instanceof FieldInsnNode fin
                        && (fin.getOpcode() == Opcodes.GETSTATIC || fin.getOpcode() == Opcodes.PUTSTATIC)) {
                    // A static field access triggers the owner's class-load → its `<clinit>` runs.
                    clinitEdge(id, fin.owner);
                } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    // A literal Net endpoint visible in this method (`new Socket("h",p)`, `new
                    // URL("https://api.stripe.com/…")`) — the decidable subset of "who it talks to",
                    // feeding the AS-EFF-008 host allowlist. Non-host strings are rejected by
                    // netHostLiteral, so this never fabricates an endpoint. Method-level (the unit the
                    // allowlist certifies); a runtime-computed host stays honestly invisible.
                    String host = netHostLiteral(s);
                    if (host != null) hostsDirect.computeIfAbsent(id, k -> new TreeSet<>()).add(host);
                } else if (insn instanceof InvokeDynamicInsnNode idin) {
                    // Lambdas & method refs: the functional-interface factory's impl method (a project
                    // `lambda$…` synthetic, or a referenced method) carries the body's effects. Edge to
                    // it so they propagate here — else passing an effectful lambda looks pure.
                    for (Object a : idin.bsmArgs) {
                        if (a instanceof Handle h && projectClasses.contains(h.getOwner()))
                            edges.get(id).add(h.getOwner().replace('/', '.') + "." + h.getName());
                    }
                }
            }
        }
    }

    /** A class's `<clinit>` runs once, at first class-load — triggered by a `new C`, a static method
     *  call on C, or a static field access on C. Edge to `C.<clinit>` from each such trigger so an
     *  effectful static initializer (`static { … }` / `static final X = readFile()`) propagates to the
     *  use site instead of looking pure. Over-approximates — the class may already be loaded by the
     *  time we reach this site — which is the SOUND direction (the I/O genuinely runs on first trigger).
     *  Only project classes that actually have a `<clinit>` (so the edge isn't dangling). */
    static void clinitEdge(String callerId, String internalOwner) {
        if (classesWithClinit.contains(internalOwner))
            edges.get(callerId).add(internalOwner.replace('/', '.') + ".<clinit>");
    }

    // entry-point annotation substrings (HTTP mappings + message listeners)
    static final List<String> MAPPING_OR_LISTENER = List.of(
            "web/bind/annotation/RequestMapping", "web/bind/annotation/GetMapping",
            "web/bind/annotation/PostMapping", "web/bind/annotation/PutMapping",
            "web/bind/annotation/DeleteMapping", "web/bind/annotation/PatchMapping",
            "kafka/annotation/KafkaListener", "amqp/rabbit/annotation/RabbitListener",
            "jms/annotation/JmsListener", "context/event/EventListener");

    static boolean annoPresent(List<AnnotationNode> anns, String descSubstring) {
        if (anns == null) return false;
        for (AnnotationNode a : anns) if (a.desc != null && a.desc.contains(descSubstring)) return true;
        return false;
    }

    static boolean annoPresentAny(List<AnnotationNode> anns, List<String> subs) {
        for (String s : subs) if (annoPresent(anns, s)) return true;
        return false;
    }

    static int firstLine(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) if (insn instanceof LineNumberNode ln) return ln.line;
        return 0;
    }

    /** Transitive supertypes (internal names) of a project type; stops at non-project ancestors. */
    static Set<String> transSupers(String internal) {
        Set<String> cached = transSupersCache.get(internal);
        if (cached != null) return cached;
        Set<String> r = new HashSet<>();
        transSupersCache.put(internal, r); // seed first to break cycles
        ClassNode cn = byName.get(internal);
        if (cn != null) {
            List<String> sup = new ArrayList<>();
            if (cn.superName != null) sup.add(cn.superName);
            if (cn.interfaces != null) sup.addAll(cn.interfaces);
            for (String s : sup) { r.add(s); r.addAll(transSupers(s)); }
        }
        return r;
    }

    /** CHA: project subtypes-or-self of `owner` that provide a concrete (name,desc) impl. */
    static List<String> chaTargets(String owner, String name, String desc) {
        List<String> out = new ArrayList<>();
        for (ClassNode c : ALL) {
            if (c.name.equals(owner) || transSupers(c.name).contains(owner)) {
                if (declaresConcrete(c, name, desc)) out.add(c.name.replace('/', '.') + "." + name);
            }
        }
        return out;
    }

    static boolean declaresConcrete(ClassNode c, String name, String desc) {
        for (MethodNode mn : c.methods)
            if (mn.name.equals(name) && mn.desc.equals(desc) && (mn.access & Opcodes.ACC_ABSTRACT) == 0)
                return true;
        return false;
    }

    static boolean isProjectIfaceOrAbstract(String internal) {
        ClassNode cn = byName.get(internal);
        return cn != null && (cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) != 0;
    }

    /** Propagate the Fs read/write detail along the SAME call graph as effects, in a separate set. A
     *  function reaching the filesystem only across a jar boundary inherits `Fs` with NO recorded kind
     *  (FS_UNKNOWN), so the report presents an empty `fs` (no claim) rather than a misleading partial. */
    static Map<String, TreeSet<String>> fsFixpoint() {
        Map<String, TreeSet<String>> fs = new HashMap<>();
        for (var e : fsDirect.entrySet()) fs.put(e.getKey(), new TreeSet<>(e.getValue()));
        for (var e : viaCross.entrySet())
            if (e.getValue().contains("Fs")) fs.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).add(FS_UNKNOWN);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                TreeSet<String> add = new TreeSet<>();
                for (String c : edges.get(caller)) {
                    var ce = fs.get(c);
                    if (ce != null) add.addAll(ce);
                }
                if (add.isEmpty()) continue;
                var set = fs.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                set.addAll(add);
                if (set.size() != before) changed = true;
            }
        }
        return fs;
    }

    static Map<String, TreeSet<String>> fixpoint() {
        Map<String, TreeSet<String>> eff = new HashMap<>();
        for (var k : direct.keySet()) eff.put(k, new TreeSet<>(direct.get(k)));
        // Seed in effects inherited via cross-jar calls (kept out of `direct` — they're not in this
        // method's own body; they appear in `inferred` and propagate transitively, like the Rust impl).
        for (var e : viaCross.entrySet()) eff.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).addAll(e.getValue());
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : edges.keySet()) {
                var set = eff.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                for (String callee : edges.get(caller)) {
                    var ce = eff.get(callee);
                    if (ce != null) set.addAll(ce);
                }
                if (set.size() != before) changed = true;
            }
        }
        return eff;
    }

    /** Classify a resolved call by target class + method — match the I/O boundary, not the package. */
    /** For a call ALREADY classified `Fs`, the read/write direction its verb implies: ["read"],
     *  ["write"], ["read","write"] (e.g. Files.copy), or [] when the verb doesn't say (so we make no
     *  claim). Keyed off the java.io / java.nio.file vocabulary — a syntactic refinement of an effect
     *  candor already proved, NOT a soundness claim. */
    static List<String> fsKind(String owner, String method) {
        if (method.equals("<init>")) { // a stream constructor reveals direction by its type
            if (owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileReader")) return List.of("read");
            if (owner.equals("java.io.FileOutputStream") || owner.equals("java.io.FileWriter")) return List.of("write");
            return List.of(); // RandomAccessFile (mode-dependent), File (no I/O) — no claim
        }
        if (method.equals("copy")) return List.of("read", "write");
        switch (method) {
            case "write": case "writeString": case "newOutputStream": case "newBufferedWriter":
            case "createFile": case "createDirectory": case "createDirectories": case "createTempFile":
            case "createTempDirectory": case "delete": case "deleteIfExists": case "move":
            case "setAttribute": case "setLastModifiedTime": case "setPosixFilePermissions":
            case "setOwner": case "createLink": case "createSymbolicLink": case "mkdir": case "mkdirs":
            case "renameTo": case "createNewFile": case "setReadable": case "setWritable":
            case "setExecutable": case "setLastModified": case "deleteOnExit": case "truncate":
                return List.of("write");
            case "readAllBytes": case "readString": case "readAllLines": case "lines":
            case "newInputStream": case "newBufferedReader": case "exists": case "notExists":
            case "isDirectory": case "isRegularFile": case "isReadable": case "isWritable":
            case "isExecutable": case "size": case "length": case "getLastModifiedTime":
            case "readAttributes": case "getAttribute": case "list": case "listFiles": case "walk":
            case "find": case "newDirectoryStream": case "isSameFile": case "mismatch":
            case "probeContentType": case "canRead": case "canWrite": case "canExecute":
            case "lastModified": case "toRealPath": case "readSymbolicLink": case "isHidden":
            case "getFreeSpace": case "getTotalSpace": case "getUsableSpace":
                return List.of("read");
            default: break;
        }
        if (method.startsWith("write") || method.equals("append")) return List.of("write");
        if (method.startsWith("read")) return List.of("read");
        return List.of();
    }

    static String classify(String owner, String method) {
        // Reflection / dynamic invocation — could call ANYTHING; honestly `Unknown`, never assumed
        // pure (SPEC §4 trust contract). This is the JVM's defining opacity, and the foundation of
        // the framework magic (Spring proxies, DI) candor can't otherwise see through.
        if (owner.equals("java.lang.reflect.Method") && method.equals("invoke")) return "Unknown";
        if (owner.equals("java.lang.reflect.Constructor") && method.equals("newInstance")) return "Unknown";
        if (owner.equals("java.lang.Class") && (method.equals("newInstance") || method.equals("forName")))
            return "Unknown";
        if (owner.equals("java.lang.reflect.Proxy") && method.equals("newProxyInstance")) return "Unknown";
        if (owner.equals("java.lang.invoke.MethodHandle") && method.startsWith("invoke")) return "Unknown";
        // Filesystem
        if (owner.equals("java.nio.file.Files")
                || owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileOutputStream")
                || owner.equals("java.io.FileReader") || owner.equals("java.io.FileWriter")
                || owner.equals("java.io.RandomAccessFile") || owner.equals("java.io.File"))
            return "Fs";
        // Network — raw sockets, java.net.http, and Spring's outbound HTTP clients
        if (owner.equals("java.net.Socket") || owner.equals("java.net.ServerSocket")
                || owner.equals("java.net.DatagramSocket") || owner.startsWith("java.net.http.")
                || owner.equals("org.springframework.web.client.RestTemplate")
                || owner.equals("org.springframework.web.client.RestClient")
                || owner.startsWith("org.springframework.web.reactive.function.client.")
                || (owner.equals("java.net.URL")
                    && (method.equals("openStream") || method.equals("openConnection") || method.equals("getContent"))))
            return "Net";
        // Messaging (Net-family)
        if (owner.equals("org.springframework.jms.core.JmsTemplate")
                || owner.equals("org.springframework.kafka.core.KafkaTemplate"))
            return "Net";
        // Database — JDBC, Spring JdbcTemplate, JPA EntityManager (Spring Data repos handled in analyze)
        if ((owner.equals("java.sql.Statement") || owner.equals("java.sql.PreparedStatement")
                || owner.equals("java.sql.CallableStatement") || owner.equals("java.sql.Connection")
                || owner.equals("java.sql.DriverManager"))
                && (method.startsWith("execute") || method.equals("getConnection")
                    || method.equals("prepareStatement") || method.equals("prepareCall")))
            return "Db";
        if (owner.equals("org.springframework.jdbc.core.JdbcTemplate")
                || owner.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                || owner.equals("jakarta.persistence.EntityManager") || owner.equals("javax.persistence.EntityManager"))
            return "Db";
        // Subprocess
        if (owner.equals("java.lang.ProcessBuilder") && method.equals("start")) return "Exec";
        if (owner.equals("java.lang.Runtime") && method.equals("exec")) return "Exec";
        // Environment / config
        if (owner.equals("java.lang.System")
                && (method.equals("getenv") || method.equals("getProperty") || method.equals("setProperty")))
            return "Env";
        if (owner.equals("org.springframework.core.env.Environment") && method.equals("getProperty")) return "Env";
        // Clock
        if (owner.equals("java.lang.System") && (method.equals("currentTimeMillis") || method.equals("nanoTime")))
            return "Clock";
        if (owner.equals("java.time.Clock")) return "Clock";
        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")
                    || owner.equals("java.time.LocalDate") || owner.equals("java.time.ZonedDateTime")))
            return "Clock";
        // Randomness
        if (owner.equals("java.util.Random") || owner.equals("java.security.SecureRandom")
                || (owner.equals("java.lang.Math") && method.equals("random")))
            return "Rand";
        // Logging
        if (owner.startsWith("org.slf4j.") || owner.startsWith("java.util.logging.")
                || owner.startsWith("org.apache.logging.log4j.") || owner.startsWith("ch.qos.logback."))
            return "Log";
        return null;
    }

    static void writeJson(Map<String, TreeSet<String>> inferred, String out) throws IOException {
        // Per-class conformance (same model as checkConformance, SPEC §5): declared = effects
        // the class's injected dependency types can supply; performed = union over its methods.
        // We attach declared/undeclared/overdeclared to each method entry so an agent can
        // consume conformance from the JSON, not just the AS-EFF diagnostics. The unit of
        // declaration in the DI idiom is the class, projected onto each of its methods.
        Map<String, TreeSet<String>> performed = new HashMap<>();
        Map<String, String> fnToClass = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> p = performed.computeIfAbsent(dc, k -> new TreeSet<>());
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                String fn = dc + "." + mn.name;
                fnToClass.put(fn, dc);
                var inf = inferred.get(fn);
                if (inf != null) p.addAll(inf);
            }
        }
        Map<String, TreeSet<String>> declaredByClass = new HashMap<>();
        for (ClassNode cn : ALL) {
            String dc = cn.name.replace('/', '.');
            TreeSet<String> declared = new TreeSet<>();
            if (cn.fields != null)
                for (FieldNode f : cn.fields) {
                    String t = fieldTypeInternal(f.desc);
                    if (t != null) declared.addAll(typeEffects(t, performed));
                }
            declaredByClass.put(dc, declared);
        }

        Map<String, TreeSet<String>> fsAcc = fsFixpoint();
        Map<String, TreeSet<String>> hostsAcc = hostsFixpoint();
        List<Map<String, Object>> entries = new ArrayList<>();
        inferred.entrySet().stream()
                // Keep a method if it has effects, is an entry point, OR its class declares a
                // capability — so a class that injects-but-never-uses one (overdeclared /
                // AS-EFF-002) is still visible in the JSON even when all its methods are pure.
                .filter(e -> {
                    if (!e.getValue().isEmpty() || entryPoints.contains(e.getKey())) return true;
                    String dc = fnToClass.get(e.getKey());
                    return dc != null && !declaredByClass.getOrDefault(dc, new TreeSet<>()).isEmpty();
                })
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> {
                    String fn = e.getKey();
                    TreeSet<String> inf = e.getValue();
                    String dc = fnToClass.get(fn);
                    TreeSet<String> declared = dc == null ? new TreeSet<>()
                            : declaredByClass.getOrDefault(dc, new TreeSet<>());
                    TreeSet<String> perf = dc == null ? new TreeSet<>()
                            : performed.getOrDefault(dc, new TreeSet<>());
                    // undeclared = inferred − declared (the AS-EFF-001 surface; Unknown excluded,
                    // it's handled by AS-EFF-003). overdeclared = class declares but never performs.
                    List<String> undeclared = inf.stream()
                            .filter(x -> !x.equals("Unknown") && !declared.contains(x))
                            .sorted().collect(Collectors.toList());
                    List<String> overdeclared = declared.stream()
                            .filter(x -> !perf.contains(x)).sorted().collect(Collectors.toList());
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("fn", fn);
                    m.put("loc", loc.getOrDefault(fn, "?"));
                    m.put("inferred", new ArrayList<>(inf));
                    m.put("direct", new ArrayList<>(direct.getOrDefault(fn, new TreeSet<>())));
                    m.put("declared", new ArrayList<>(declared));
                    m.put("undeclared", undeclared);
                    m.put("overdeclared", overdeclared);
                    m.put("entryPoint", entryPoints.contains(fn));
                    m.put("unresolved", inf.contains("Unknown")); // trust contract (SPEC §4)
                    m.put("hash", hashOf.getOrDefault(fn, "")); // cross-jar join key (SPEC §2)
                    // Effect-relevant local call graph (SPEC §2 `calls`): the EFFECTFUL local callees,
                    // so a consumer can answer "who calls X?" from the report without re-analysis.
                    // Omitted when empty.
                    List<String> calls = edges.getOrDefault(fn, Set.of()).stream()
                            .filter(c -> {
                                TreeSet<String> ce = inferred.get(c);
                                return ce != null && !ce.isEmpty();
                            })
                            .sorted().collect(Collectors.toList());
                    if (!calls.isEmpty()) m.put("calls", calls);
                    // Fs read/write detail (SPEC §2 `fs`): the access kind, when known AND complete.
                    // Empty when unknown, when the fn performs no Fs, or when reached cross-jar
                    // (FS_UNKNOWN) — never a misleading partial. Omitted when empty.
                    TreeSet<String> fk = fsAcc.get(fn);
                    if (inf.contains("Fs") && fk != null && !fk.contains(FS_UNKNOWN)) {
                        List<String> kinds = fk.stream().filter(x -> !x.equals(FS_UNKNOWN)).sorted()
                                .collect(Collectors.toList());
                        if (!kinds.isEmpty()) m.put("fs", kinds);
                    }
                    // Literal Net endpoints statically visible from this method (SPEC §2 `hosts`): the
                    // decidable subset of "who it talks to", feeding the AS-EFF-008 allowlist. Omitted
                    // when none are visible (a runtime-computed host, or no Net) — never a completeness claim.
                    TreeSet<String> hk = hostsAcc.get(fn);
                    if (inf.contains("Net") && hk != null && !hk.isEmpty())
                        m.put("hosts", new ArrayList<>(hk));
                    entries.add(m);
                });
        // v0.2 self-describing envelope (candor-spec §2): a provenance header + the function entries.
        // Readers still accept the legacy v0.1 bare array (see loadBaseline) during migration.
        String[] prov = provenance();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("version", prov[0]);
        header.put("toolchain", prov[1]);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("candor", header);
        envelope.put("functions", entries);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(envelope);
        Files.writeString(Path.of(out), json);
        System.err.println("candor-java: wrote " + entries.size() + " entries (@" + prov[0] + ") to " + out);
    }

    /** Engine provenance for the v0.2 envelope (candor-spec §2.1): the build id + toolchain baked into
     *  a resource at build time, so the report reflects the BINARY that ran rather than the source
     *  tree. Falls back to "unknown" / the running JDK when the resource is absent. */
    static String[] provenance() {
        String version = "unknown";
        String toolchain = "jvm-" + System.getProperty("java.version", "?");
        try (var in = Candor.class.getResourceAsStream("/candor/build-info.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                version = p.getProperty("version", version);
                toolchain = p.getProperty("toolchain", toolchain);
            }
        } catch (IOException ignored) {
        }
        return new String[] {version, toolchain};
    }
}
