package io.poly.candor;

import io.poly.candor.model.Effect;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SOUNDNESS R492 / R727 — the GENERATED member -> effect table for the κ-covered framework namespaces.
 *
 * <p>{@link Rules#KAPPA_COVERED_PREFIXES} suppresses the {@code invisible} disclosure for a whole namespace, so a
 * member of a covered framework that the hand-written classifier does not name read SILENTLY PURE — groovy's
 * {@code ResourceGroovyMethods.deleteDir}, commons-csv's {@code CSVParser.parse(File, …)}, Spring's
 * {@code FileSystemResource.contentLength}, JNA's {@code Native.loadLibrary} (squatting on {@code com.sun}):
 * the caller absent from {@code functions}, {@code deny Fs}/{@code deny Exec} exit 0 over code that really does it.
 *
 * <p>The table is DERIVED, never written by hand: {@code soundness/kappa_table/derive.sh} scans each surveyed
 * framework jar with this engine (with the table switched off, so it never feeds itself) and closes each
 * consumer-callable member over STATICALLY RESOLVED edges to the bodies whose {@code direct} effects the scan
 * reported — the full rule, the version policy and the source artefacts are in that script, in
 * {@code FrameworkReachGen.java}, and in the table's own header. {@code KappaFrameworkReachTest} fails on a
 * hand-edited table (content checksum) and on a table older than its generator (generator checksum).
 *
 * <p><b>It only ADDS.</b> A charge here is unioned into the call's effects as a SIDE charge — {@code effect} is
 * not assigned, so every {@code effect == null} fallback downstream still runs, and no hand-written charge is
 * replaced. A member ABSENT from the table keeps exactly the treatment it had before the table existed; nothing
 * reads absence as purity. A side charge with no named locator leaves its surface {@code incomplete}
 * ({@link Candor#markUnnamedSideCharge}), so a sibling literal cannot certify it.
 */
final class FrameworkReach {
    private FrameworkReach() {}

    static final String RESOURCE = "/candor/framework-reach.tsv";

    /** The generator's switch. Read once; never set by a user-facing option. */
    static final boolean DISABLED = "off".equals(System.getProperty("candor.frameworkReach"));

    private static volatile Map<String, List<Effect>> table;

    /** The effects the table charges a call that resolves to {@code internalOwner.name+desc}, or an empty list. */
    static List<Effect> charges(String internalOwner, String name, String desc) {
        if (DISABLED) return List.of();
        Map<String, List<Effect>> t = table;
        if (t == null) t = load();
        List<Effect> e = t.get(internalOwner + "." + name + desc);
        return e == null ? List.of() : e;
    }

    // ── THE RESIDUE: framework members the table cannot vouch for (SOUNDNESS R492/R727) ──────────────────────
    static final String HEDGE_RESOURCE = "/candor/framework-hedge.tsv";
    private static volatile Map<String, String> hedge;
    private static final java.util.Set<String> SURVEYED = new java.util.HashSet<>();
    private static final java.util.Set<String> JDK_PKGS = new java.util.HashSet<>();

    /** Why a call into a κ-covered FRAMEWORK owner the table does not charge must still disclose, or null when the
     *  grant's silence is earned. The grant used to certify all of these pure; the table now separates them:
     *  <ul><li>{@code "A"} — the call resolves to NO body in the surveyed jars (an abstract or interface member,
     *  or native): which implementation runs is decided at run time, by code the table never read.</li>
     *  <li>{@code "U"} — every body it resolves to is one this engine's own scan of the framework could read only
     *  as {@code Unknown}.</li>
     *  <li>{@code "C"} — SOUNDNESS R1468: the member's surveyed closure reaches a dispatch the table cannot follow
     *  (an abstract member none of whose surveyed implementers carries the effect, or an unsurveyed owner), where a
     *  NAME rule's charge used to stand in for it. Disclosed as {@code Unknown[dispatch:<that member>]}
     *  ({@link #closureTarget}), beside a charge or alone — not charged with an effect the body may not perform.</li>
     *  <li>{@code "X"} — the owner is under a covered framework prefix but in no surveyed jar (e.g.
     *  {@code org.hibernate.criterion}, the {@code javax.*} APIs no jar here ships).</li></ul>
     *  Never for the JDK ({@code J} lines: soundness/kappa_table/jdk-packages.txt, JDK 21), the language runtimes
     *  (kotlin, scala, groovy) or the logging frameworks: those keep the grant. A member the table EXAMINED and
     *  found pure gets null — that silence is a measurement, and disclosing it would be false. */
    static String hedgeKind(String internalOwner, String name, String desc) {
        if (DISABLED) return null;
        int sl = internalOwner.lastIndexOf('/');
        if (sl <= 0) return null;
        String pkg = internalOwner.substring(0, sl).replace('/', '.');
        if (!Candor.kappaCovers(pkg)) return null;
        Map<String, String> h = hedge == null ? loadHedge() : hedge;
        if (JDK_PKGS.contains(pkg) || runtimeOrLogging(internalOwner)) return null;
        String key = internalOwner + "." + name + desc;
        // SOUNDNESS R1096 — a U line beside a table charge: the charge is an OVERRIDE's, the declared body is still
        // Unknown-only, and both are what a call can run. And an A line beside one: the member's overrides were too
        // many to charge (the engine's bounded CHA) and can do more than its charge says. Before R1096 neither kind
        // was ever written for a charged member, so this reads only R1096's lines.
        if (!charges(internalOwner, name, desc).isEmpty()) {
            String k = h.get(key);
            return "U".equals(k) || "A".equals(k) || "C".equals(k) ? k : null;   // R1096: also a BROAD override fan-out; R1468 C
        }
        String k = h.get(key);
        if (k != null) return k;
        return SURVEYED.contains(internalOwner) ? null : "X";
    }

    // ── SOUNDNESS R1052(b,c) — NAME-RULED MEMBERS WHOSE SURVEYED BODY IS A PROVEN-PURE ACCESSOR ────────────────────
    private static final java.util.Set<String> PURE = new java.util.HashSet<>();
    /** The generator's input while it scans the framework jars with the table off: the P list it computed from the
     *  bytecode just before (derive.sh step 1b). Never set by a user-facing option. */
    static final String PURE_OVERRIDE = System.getProperty("candor.frameworkPure");
    private static volatile java.util.Set<String> pureOverride;

    /** Whether the call {@code internalOwner.name+desc} resolves, in every surveyed artefact, to a body that does
     *  nothing but read or store a field (or forward to one that does) — while a NAME rule (the model-SDK blanket, or
     *  an owner-blanket classifier rule) charges it. FrameworkReachGen#computePure says exactly which shapes count.
     *  The caller drops that name rule's charge and NOTHING else: the table, the hedge and every other rule still
     *  apply, and a member with no P line keeps the rule. */
    static boolean provenPure(String internalOwner, String name, String desc) {
        String key = internalOwner + "." + name + desc;
        if (PURE_OVERRIDE != null) {
            java.util.Set<String> o = pureOverride;
            if (o == null) o = loadPureOverride();
            return o.contains(key);
        }
        if (DISABLED) return false;
        if (hedge == null) loadHedge();
        return PURE.contains(key);
    }

    private static synchronized java.util.Set<String> loadPureOverride() {
        if (pureOverride != null) return pureOverride;
        try {
            pureOverride = new java.util.HashSet<>(java.nio.file.Files.readAllLines(java.nio.file.Path.of(PURE_OVERRIDE)));
        } catch (IOException ex) {
            throw new IllegalStateException("candor: cannot read candor.frameworkPure=" + PURE_OVERRIDE, ex);
        }
        return pureOverride;
    }

    // ── SOUNDNESS R1478 — owner-wide rules that yield to the table at a consumer's call, member by member ──────────────
    /** {@code internalOwner.name} (every descriptor) of members an OWNER-WIDE classifier rule charges and which were
     *  EXECUTED doing nothing at the call, while the table answers them with a disclosure (a U or C line) because their
     *  closure reaches a dispatch it cannot follow. Hand-listed, not derived: R1478's lane measured the general form
     *  ("drop the rule wherever no surveyed implementer of the opaque closure carries it") losing a reactive repository's
     *  Db through an unsurveyed driver, and surveying the jars these closures stop at (spring-aop, spring-expression,
     *  micrometer) was measured NOT to make them followable (Redis's proxy factory still reaches
     *  AdvisedSupportListener.activated, Cassandra's mapping interfaces stay abstract). Each entry carries its execution:
     *  <ul><li>RedisTemplate.bound{Geo,List,Set,Stream,Value,ZSet}Ops build a spring-aop proxy over the key, no driver
     *  call; the Bound*Operations handed back is itself rule-charged (the {@code *Operations} rule), so {@code .get()},
     *  {@code .size()}, {@code .add()} keep Db and each was executed opening a connection. {@code boundHashOps} is NOT
     *  listed: its own table row reaches Db through the {@code RedisOperations.opsForHash()} rule in its lambda.</li>
     *  <li>CassandraTemplate.getTableName (a CqlIdentifier from the mapping context) and setApplicationContext (stores the
     *  context, builds entity callbacks): neither touches the CqlSession; count/truncate on the same template do.</li>
     *  <li>RabbitTemplate's constructors: {@code new RabbitTemplate(cf)} opens nothing, with the factory idle or holding a
     *  live connection; convertAndSend on that object sends.</li></ul>
     *
     *  <p>ONLY AT A CONSUMER'S CALL, with the table on. The generator's own scans run with the table off, so library
     *  bodies keep the rule's charge — and that is load-bearing: carving these members out of the CLASSIFIER instead
     *  was built and measured, and it moved seven spring-rabbit rows off {@code Net}, two of them real
     *  (logback/log4j2 {@code AmqpAppender.setUpExchangeDeclaration()} declares the exchange on the wire when the
     *  connection factory already holds a connection — EXECUTED — through
     *  {@code CachingConnectionFactory.addConnectionListener} calling {@code onCreate} at once, an internal override the
     *  table does not follow; the rule on {@code new RabbitAdmin(cf)}'s template was the only charge covering it). */
    private static final java.util.Set<String> YIELD_TO_TABLE = java.util.Set.of(
            "org/springframework/data/redis/core/RedisTemplate.boundGeoOps",
            "org/springframework/data/redis/core/RedisTemplate.boundListOps",
            "org/springframework/data/redis/core/RedisTemplate.boundSetOps",
            "org/springframework/data/redis/core/RedisTemplate.boundStreamOps",
            "org/springframework/data/redis/core/RedisTemplate.boundValueOps",
            "org/springframework/data/redis/core/RedisTemplate.boundZSetOps",
            "org/springframework/data/cassandra/core/CassandraTemplate.getTableName",
            "org/springframework/data/cassandra/core/CassandraTemplate.setApplicationContext",
            "org/springframework/amqp/rabbit/core/RabbitTemplate.<init>");

    /** Whether a consumer's call to {@code internalOwner.name+desc} drops its owner-wide rule's charge for the table's
     *  answer: a {@link #YIELD_TO_TABLE} member that the table answers — a charge, or a hedge line that discloses it.
     *  A member the table has no line for keeps the rule (the over-charge, never a silence). */
    static boolean ruleYieldsToTable(String internalOwner, String name, String desc) {
        if (DISABLED || PURE_OVERRIDE != null || !YIELD_TO_TABLE.contains(internalOwner + "." + name)) return false;
        return !charges(internalOwner, name, desc).isEmpty() || hedgeKind(internalOwner, name, desc) != null;
    }

    // ── SOUNDNESS R1097 — a public member overridden in ANOTHER surveyed jar ─────────────────────────────────────
    private static final Map<String, List<String>> XJAR = new HashMap<>();

    /** The classes, each shipped in a surveyed jar OTHER than the one declaring {@code internalOwner}, whose override
     *  of {@code name+desc} can do more than the table's row (or the member's NAME rule) says — or an empty list.
     *  The table cannot charge them: whether that other jar is on a consumer's class path is not something it knows
     *  (FrameworkReachGen#crossJar). The call site decides: an overriding class the consumer's scan or a chained
     *  report can see is resolved through that body, and one it cannot see is disclosed (Candor#frameworkCrossJar). */
    static List<String> crossJarOverriders(String internalOwner, String name, String desc) {
        if (DISABLED) return List.of();
        if (hedge == null) loadHedge();
        List<String> l = XJAR.get(internalOwner + "." + name + desc);
        return l == null ? List.of() : l;
    }

    // ── SOUNDNESS R1468 — a closure the table cannot follow, disclosed rather than charged with a rule's stand-in ─────
    private static final Map<String, String> CLOSURE = new HashMap<>();

    /** For a {@code C} member, the dispatch its surveyed closure reaches and the table cannot follow
     *  ({@code owner.name}, dotted), which its {@code Unknown[dispatch:…]} names; otherwise null. */
    static String closureTarget(String internalOwner, String name, String desc) {
        if (DISABLED) return null;
        if (hedge == null) loadHedge();
        return CLOSURE.get(internalOwner + "." + name + desc);
    }

    static boolean runtimeOrLogging(String internalName) {
        for (String p : new String[] { "kotlin/", "scala/", "groovy/", "org/codehaus/groovy/", "org/slf4j/",
                "org/apache/commons/logging/", "org/apache/logging/", "ch/qos/logback/" })
            if (internalName.startsWith(p)) return true;
        return false;
    }

    // ── SOUNDNESS R1509 — THE SURVEYED HIERARCHY ─────────────────────────────────────────────────────────────────────
    private static final Map<String, List<String>> SUPERS = new HashMap<>();

    /** A surveyed framework class's DIRECT supertypes (superclass first, then interfaces; {@code Object} omitted), from
     *  the table's {@code H} lines, or null when the table has none for it (not surveyed, a JDK class, or only
     *  {@code Object} above it). The consumer's class path does not carry the framework's bytes, so without this a
     *  consumer class {@code P extends fw.Base} never reaches {@code fw.Iface}, which {@code fw.Base} implements:
     *  Cha#crossBoundaryTargets walks it. Null while the table is off, like every other read here. */
    static List<String> surveyedSupers(String internalName) {
        if (DISABLED) return null;
        if (hedge == null) loadHedge();
        return SUPERS.get(internalName);
    }

    /** SOUNDNESS R1509 — whether {@code internalName} is in a JDK package (the table's {@code J} lines, or {@code java/}). */
    static boolean jdkOwned(String internalName) {
        if (internalName.startsWith("java/")) return true;
        int sl = internalName.lastIndexOf('/');
        if (sl <= 0 || DISABLED) return false;
        if (hedge == null) loadHedge();
        return JDK_PKGS.contains(internalName.substring(0, sl).replace('/', '.'));
    }

    static int hedgeSize() { return hedge == null ? loadHedge().size() : hedge.size(); }

    private static synchronized Map<String, String> loadHedge() {
        if (hedge != null) return hedge;
        Map<String, String> m = new HashMap<>(1 << 17);
        try (InputStream in = FrameworkReach.class.getResourceAsStream(HEDGE_RESOURCE)) {
            if (in == null) throw new IllegalStateException("candor: bundled resource " + HEDGE_RESOURCE + " is missing");
            BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            for (String line; (line = r.readLine()) != null; ) {
                if (line.isEmpty() || line.charAt(0) == '#') continue;
                int tab = line.indexOf('\t');
                String kind = line.substring(0, tab), v = line.substring(tab + 1);
                switch (kind) {
                    case "J" -> JDK_PKGS.add(v);
                    case "S" -> SURVEYED.add(v);
                    case "A", "U" -> m.put(v, kind);
                    case "C" -> {      // SOUNDNESS R1468: key <TAB> the unfollowable member its closure reaches
                        int t2 = v.indexOf('\t');
                        if (t2 <= 0) throw new IllegalStateException("candor: " + HEDGE_RESOURCE + " bad line: " + line);
                        m.put(v.substring(0, t2), kind);
                        CLOSURE.put(v.substring(0, t2), v.substring(t2 + 1));
                    }
                    case "P" -> PURE.add(v);
                    case "H" -> {      // SOUNDNESS R1509: a surveyed class <TAB> its direct supertypes, comma-separated
                        int t2 = v.indexOf('\t');
                        if (t2 <= 0) throw new IllegalStateException("candor: " + HEDGE_RESOURCE + " bad line: " + line);
                        SUPERS.put(v.substring(0, t2), List.of(v.substring(t2 + 1).split(",")));
                    }
                    case "O" -> {      // SOUNDNESS R1097: key <TAB> overriding classes, comma-separated
                        int t2 = v.indexOf('\t');
                        if (t2 <= 0) throw new IllegalStateException("candor: " + HEDGE_RESOURCE + " bad line: " + line);
                        XJAR.put(v.substring(0, t2), List.of(v.substring(t2 + 1).split(",")));
                    }
                    default -> throw new IllegalStateException("candor: " + HEDGE_RESOURCE + " bad line: " + line);
                }
            }
        } catch (IOException ex) {
            throw new IllegalStateException("candor: cannot read " + HEDGE_RESOURCE, ex);
        }
        // A stripped or placeholder list would read every JDK package as a FRAMEWORK one and flood Unknown.
        if (JDK_PKGS.isEmpty() || SURVEYED.isEmpty())
            throw new IllegalStateException("candor: " + HEDGE_RESOURCE + " carries no J/S lines — regenerate it");
        hedge = m;
        return m;
    }

    static int size() { return DISABLED ? 0 : (table == null ? load() : table).size(); }

    private static synchronized Map<String, List<Effect>> load() {
        if (table != null) return table;
        Map<String, List<Effect>> m = new HashMap<>(1 << 16);
        try (InputStream in = FrameworkReach.class.getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException("candor: bundled resource " + RESOURCE + " is missing");
            BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            for (String line; (line = r.readLine()) != null; ) {
                if (line.isEmpty() || line.charAt(0) == '#') continue;
                int tab = line.indexOf('\t');
                EnumSet<Effect> es = EnumSet.noneOf(Effect.class);
                for (String n : line.substring(tab + 1).split(",")) {
                    Effect e = Effect.fromSpecName(n);
                    if (e == null || e == Effect.UNKNOWN)
                        throw new IllegalStateException("candor: " + RESOURCE + " names a non-effect: " + line);
                    es.add(e);
                }
                m.put(line.substring(0, tab), Collections.unmodifiableList(new ArrayList<>(es)));
            }
        } catch (IOException ex) {
            throw new IllegalStateException("candor: cannot read " + RESOURCE, ex);
        }
        table = m;
        return m;
    }
}
