///usr/bin/env jbang "$0" "$@"
//DEPS com.ibm.wala:com.ibm.wala.core:1.6.7
//DEPS com.ibm.wala:com.ibm.wala.util:1.6.7
//DEPS com.ibm.wala:com.ibm.wala.shrike:1.6.7
//JAVA 21

import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.classLoader.Language;
import com.ibm.wala.ipa.callgraph.AnalysisOptions.ReflectionOptions;

import java.io.File;
import java.util.*;

/**
 * The precision baseline for RQ4a: a mature whole-program points-to call graph (WALA, 0-CFA — the
 * standard *precise* mode). It answers, on the same fixture classes candor scans, the reachability
 * question the effect gate answers: does `pricing.Pricing.quote` reach `java.net.Socket`?
 *
 * BFS over call-graph successor edges from the quote node (true reachability, not mere node presence).
 *
 *   jbang WalaCheck.java <classes-dir>
 *
 * Ported fixture   -> REACHES   (0-CFA resolves the single-impl port; agrees with candor's determined Net)
 * Reflective variant -> DOES NOT REACH (0-CFA has no allocation flowing to the reflectively-built impl,
 *                       so it drops the edge — a SILENT under-report / false all-clear. candor discloses
 *                       Unknown on the same code instead of dropping it.)
 */
public class WalaCheck {
    public static void main(String[] args) throws Exception {
        String classesDir = args[0];
        File excl = File.createTempFile("wala-excl", ".txt");
        AnalysisScope scope = AnalysisScopeReader.instance.makeJavaBinaryAnalysisScope(classesDir, excl);
        IClassHierarchy cha = ClassHierarchyFactory.make(scope);
        Iterable<Entrypoint> entries = Util.makeMainEntrypoints(scope, cha, "Lapp/Main");
        AnalysisOptions options = new AnalysisOptions(scope, entries);
        // Reflection knob: "none" = the precision/scalability-oriented config (no Class.forName modeling);
        // "full" (default) = conservative reflection modeling. The tradeoff is the whole point.
        String refl = args.length > 1 ? args[1] : "full";
        options.setReflectionOptions(refl.equalsIgnoreCase("none") ? ReflectionOptions.NONE : ReflectionOptions.FULL);
        System.out.println("WALA reflection modeling: " + options.getReflectionOptions());
        CallGraphBuilder<?> builder = Util.makeZeroCFABuilder(Language.JAVA, options, new AnalysisCacheImpl(), cha);
        CallGraph cg = builder.makeCallGraph(options, null);

        // Seed BFS at every node whose method is pricing.Pricing.quote.
        Deque<CGNode> work = new ArrayDeque<>();
        Set<CGNode> seen = new HashSet<>();
        for (CGNode n : cg) {
            if (n.getMethod().getSignature().contains("pricing.Pricing.quote")) { work.add(n); seen.add(n); }
        }
        if (work.isEmpty()) { System.out.println("WALA: no node for pricing.Pricing.quote (?)"); System.exit(2); }

        boolean reachesSocket = false;
        String witness = null;
        while (!work.isEmpty()) {
            CGNode n = work.poll();
            String sig = n.getMethod().getSignature();
            if (sig.startsWith("java.net.Socket.") ) { reachesSocket = true; witness = sig; break; }
            for (Iterator<CGNode> it = cg.getSuccNodes(n); it.hasNext(); ) {
                CGNode s = it.next();
                if (seen.add(s)) work.add(s);
            }
        }

        System.out.println("WALA 0-CFA call graph: " + cg.getNumberOfNodes() + " nodes; "
                + "reachable from quote: " + seen.size());
        if (reachesSocket) {
            System.out.println("WALA VERDICT: quote REACHES java.net.Socket  (witness: " + witness + ")");
            System.out.println("  -> agrees with candor's determined Net on this code.");
        } else {
            System.out.println("WALA VERDICT: quote does NOT reach java.net.Socket");
            System.out.println("  -> 0-CFA dropped the reflectively-dispatched edge: a SILENT under-report");
            System.out.println("     (a false all-clear). candor discloses Unknown on the same code.");
        }
        System.exit(reachesSocket ? 0 : 1);
    }
}
