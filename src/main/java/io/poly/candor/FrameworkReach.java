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
