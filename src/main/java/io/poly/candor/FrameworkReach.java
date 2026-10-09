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
     *  <li>{@code "X"} — the owner is under a covered framework prefix but in no surveyed jar (e.g.
     *  {@code org.hibernate.criterion}, the {@code javax.*} APIs no jar here ships).</li></ul>
     *  Never for the JDK ({@code J} lines, generated from the JDK's own module list), the language runtimes
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
        if (!charges(internalOwner, name, desc).isEmpty()) return null;
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

    static boolean runtimeOrLogging(String internalName) {
        for (String p : new String[] { "kotlin/", "scala/", "groovy/", "org/codehaus/groovy/", "org/slf4j/",
                "org/apache/commons/logging/", "org/apache/logging/", "ch/qos/logback/" })
            if (internalName.startsWith(p)) return true;
        return false;
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
                    case "P" -> PURE.add(v);
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
