package io.poly.candor;   // compiled by soundness/kappa_table/derive.sh against the engine jar; not part of the build

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.poly.candor.model.Effect;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.Type;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * SOUNDNESS R492 / R727 — generate {@code src/main/resources/candor/framework-reach.tsv}, the machine-derived
 * member -> effect table for the κ-covered framework namespaces.
 *
 * <p>Args: {@code <out.tsv> <witness.tsv> <header-file> (<jar> <report.json>)...}. Each report is the ENGINE's
 * own scan of that jar, taken with {@code -Dcandor.frameworkReach=off} so the table never feeds itself.
 *
 * <p><b>What a charge means.</b> A row {@code owner.name+desc -> E} says: in EVERY surveyed artefact that declares
 * {@code owner}, the body the JVM resolves for that call (JVMS 5.4.3.3 — the static target, superclass chain
 * first, then superinterface defaults) reaches a body to which the engine's own scan attributed {@code E} in
 * {@code direct}, along edges that are each STATICALLY RESOLVED: invokestatic/special, the static target of an
 * invokevirtual/interface (never its overriders), and a lambda/method-reference implementation handle. A static
 * member or constructor also runs the {@code <clinit>} of its own class and superclasses (JVMS 5.5) — the class the
 * consumer NAMES, which is the edge the engine itself draws at a consumer's static access ({@code clinitEdge} /
 * {@code inheritDepClinit}). The {@code <clinit>} of a class a library body touches INTERNALLY is not followed:
 * measured over the 117 surveyed jars, those edges added 19,629 rows, and their leaves are one-time framework
 * bootstrap — JCL/SLF4J reading their classpath config through a {@code URL} the classifier must charge {@code Net},
 * groovy's plugin and DGM loading — which made e.g. struts 1.2.9 {@code RequestProcessor.processActionPerform}
 * read {@code Net} through {@code RequestUtils.<clinit> -> LogFactory.getLog}, the exact charge R727 declined as a
 * fabrication on 1.2.9. Leaving them out is not a purity claim: those members keep the treatment they had.
 * {@code direct}, not {@code inferred}: {@code inferred}
 * includes the engine's CHA fan-out, which in a library scan joins every {@code hashCode} to every other
 * (measured: beanutils {@code DynaProperty.hashCode -> Clock,Db,Log} through {@code ResultSetIterator.hasNext}),
 * and a consumer calling the member does not run those bodies. Only concrete effects: an {@code Unknown} in a
 * library body is the engine saying it cannot see, which is not a charge.
 *
 * <p><b>Absence is not a claim.</b> A member with no row keeps exactly the treatment it had before the table
 * existed (the κ grant). The table can only ADD a charge; nothing reads a missing row as purity.
 *
 * <p><b>Versions.</b> When two surveyed artefacts declare the same owner (struts 1.2.9 / 1.3.10), the row carries
 * the INTERSECTION of their charges; a charge present in one version only is written to the witness file as
 * {@code DIVERGENT} and charged nowhere.
 */
public class FrameworkReachGen {
    static final Effect[] CONC = { Effect.CLIPBOARD, Effect.CLOCK, Effect.DB, Effect.ENV, Effect.EXEC, Effect.FS,
            Effect.IPC, Effect.LLM, Effect.LOG, Effect.NET, Effect.RAND };

    /** THE LOGGING FRAMEWORKS ARE THE CLASSIFIER'S FRONTIER, NOT TABLE INPUT — neither rows nor closure targets.
     *  The classifier already charges logging where it happens, at the emit call ({@code Logger.info} -> {@code Log});
     *  what their bodies reach BEYOND that is one-time configuration discovery (JCL/SLF4J/log4j scanning the class
     *  path for their config and bindings — a {@code URL} read the classifier must charge {@code Net}). Composed
     *  through the table, that put {@code Fs}/{@code Net} on {@code LoggerFactory.getLogger} itself and on every
     *  framework member that obtains a logger (measured: see the R492 commit), i.e. on every class in every app
     *  that holds one. Cut, those members keep exactly the treatment they had; nothing is claimed pure. */
    static final String[] LOGGING_FRONTIER = { "org/slf4j/", "org/apache/commons/logging/", "org/apache/logging/",
            "ch/qos/logback/" };

    static String hedgeOut;

    /** The JDK's own packages: the checked-in list {@code jdk-packages.txt} (derive.sh passes it as
     *  {@code -Dframework.jdkPackages}). NOT the module list of the JDK this generator happens to run on: that was
     *  the original reading, and it made the table a function of the developer's {@code JAVA_HOME} — measured
     *  2026-10-09, a JDK 17 run wrote {@code J com.sun.jarsigner} and nine {@code com.sun.tools.sjavac*} lines that a
     *  JDK 21 run (CI's) does not, while omitting {@code java.lang.foreign}, so a JDK 21 program's FFM calls read
     *  {@code X} (an "unsurveyed framework") and disclosed a false Unknown. And the OS moved it too: a Linux
     *  image ships {@code sun.awt.X11}, a macOS one {@code sun.lwawt.macosx}, so CI (Linux) could never reproduce a
     *  Mac-generated table. The list is the JDK 21 images for Linux, macOS and Windows, unioned: their exported
     *  packages are identical (227) and are exactly the ones SOUNDNESS R814's census of the classifier's JDK
     *  frontier read, so a {@code J} line keeps the grant only where that census looked. A JDK 17-only package
     *  ({@code com.sun.jarsigner}, {@code jdk.incubator.foreign}) or a JDK 22+ one ({@code java.lang.classfile},
     *  {@code javax.sound}) stays {@code X}: an Unknown, not a silence, until the census covers that release.
     *  Regenerate it with {@code --jdk-packages <out> <java.home>...}. */
    static List<String> jdkPackages() {
        String f = System.getProperty("framework.jdkPackages");
        if (f == null) throw new IllegalStateException("framework-reach: -Dframework.jdkPackages=<jdk-packages.txt> is "
                + "required (the JDK package list is a checked-in input, never the running JDK's)");
        TreeSet<String> s = new TreeSet<>();
        try {
            for (String l : Files.readAllLines(Path.of(f), StandardCharsets.UTF_8))
                if (!l.isBlank() && !l.startsWith("#")) s.add(l.strip());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("framework-reach: cannot read " + f, e);
        }
        if (s.isEmpty()) throw new IllegalStateException("framework-reach: " + f + " lists no packages");
        return new ArrayList<>(s);
    }

    /** {@code --jdk-packages <out> <java.home>...}: write the union of the packages each named JDK image ships,
     *  read from its own modules' descriptors over {@code jrt:/} (so no JDK has to be the one running this) —
     *  the set {@code ModuleFinder.ofSystem()} gives when that JDK is the runtime. */
    static void jdkPackagesOut(String[] a) throws Exception {
        TreeSet<String> s = new TreeSet<>();
        StringBuilder hdr = new StringBuilder();
        hdr.append("# The JDK's packages, for soundness/kappa_table (FrameworkReachGen#jdkPackages): the UNION over the\n")
           .append("# JDK images below, read from each image's module descriptors. A checked-in INPUT of the table, hashed\n")
           .append("# into its generator-sha256: the table must not depend on the JAVA_HOME or OS it was generated on.\n")
           .append("# Which images, and why JDK 21 only: FrameworkReachGen#jdkPackages.\n")
           .append("# Regenerate: java -cp <tool>:<engine-all.jar> io.poly.candor.FrameworkReachGen --jdk-packages \\\n")
           .append("#   soundness/kappa_table/jdk-packages.txt <java.home>...\n");
        for (int i = 2; i < a.length; i++) {
            Path home = Path.of(a[i]);
            String release = "";
            for (String l : Files.readAllLines(home.resolve("release"), StandardCharsets.UTF_8))
                if (l.startsWith("JAVA_VERSION=") || l.startsWith("IMPLEMENTOR=") || l.startsWith("OS_NAME=") || l.startsWith("OS_ARCH="))
                    release += " " + l;
            int before = s.size(), n = 0;
            try (java.nio.file.FileSystem fs = java.nio.file.FileSystems.newFileSystem(java.net.URI.create("jrt:/"),
                    Map.of("java.home", home.toString()));
                 java.util.stream.Stream<Path> ms = Files.list(fs.getPath("/modules"))) {
                for (Path m : (Iterable<Path>) ms::iterator) {
                    Path mi = m.resolve("module-info.class");
                    if (!Files.exists(mi)) continue;
                    // ASM, not ModuleDescriptor.read: a newer image's class-file version is unreadable to an older runtime
                    ClassNode cn = new ClassNode();
                    new ClassReader(Files.readAllBytes(mi)).accept(cn, ClassReader.SKIP_CODE);
                    if (cn.module != null && cn.module.packages != null)
                        for (String pk : cn.module.packages) { s.add(pk.replace('/', '.')); n++; }
                }
            }
            hdr.append("# image:").append(release).append(" — ").append(n).append(" packages, ")
               .append(s.size() - before).append(" not in the images above\n");
        }
        StringBuilder sb = new StringBuilder(hdr);
        sb.append("# packages ").append(s.size()).append('\n');
        for (String p : s) sb.append(p).append('\n');
        Files.writeString(Path.of(a[1]), sb.toString(), StandardCharsets.UTF_8);
    }

    /** A language runtime or the logging frontier: neither is hedged (the JDK is not surveyed at all). */
    static boolean runtimeOwner(String internalName) {
        for (String p : new String[] { "kotlin/", "scala/", "groovy/", "org/codehaus/groovy/" })
            if (internalName.startsWith(p)) return true;
        return loggingFrontier(internalName);
    }

    static boolean loggingFrontier(String internalName) {
        for (String p : LOGGING_FRONTIER) if (internalName.startsWith(p)) return true;
        return false;
    }

    static int bit(String specName) {
        for (int i = 0; i < CONC.length; i++) if (CONC[i].specName().equals(specName)) return 1 << i;
        return 0;
    }

    static String names(int mask) {
        StringJoiner j = new StringJoiner(",");
        for (int i = 0; i < CONC.length; i++) if ((mask & (1 << i)) != 0) j.add(CONC[i].specName());
        return j.toString();
    }

    // ── the class universe ──────────────────────────────────────────────────────────────────────────────
    static final List<String> jarNames = new ArrayList<>();
    static final List<Map<String, ClassNode>> jarClasses = new ArrayList<>();
    static final Map<String, List<Integer>> classJars = new HashMap<>();

    // ── nodes: every method with a body, id'd in sorted order ──────────────────────────────────────────
    static final Map<String, Integer> nodeId = new HashMap<>();   // "j|owner.name+desc"
    static final List<String> nodeKey = new ArrayList<>();
    static final List<MethodNode> nodeMethod = new ArrayList<>();
    static final List<String> nodeOwner = new ArrayList<>();
    static final List<Integer> nodeJar = new ArrayList<>();
    /** Bodies the engine's own scan of the jar reported as ONLY {@code Unknown} (its `inferred`). */
    static final Set<Integer> UNK_ONLY = new HashSet<>();
    /** Framework members a consumer can call whose body the table cannot vouch for: "A" — resolution reaches no
     *  body (abstract/interface/native: the implementer is chosen at run time); "U" — every resolved body is one the
     *  scan could read only as Unknown. Absent here and absent from the table = examined and pure. */
    static final TreeMap<String, String> HEDGE = new TreeMap<>();
    static final TreeSet<String> SURVEYED = new TreeSet<>();

    static Integer node(int j, String owner, String nameDesc) { return nodeId.get(j + "|" + owner + "." + nameDesc); }

    public static void main(String[] a) throws Exception {
        if (a.length > 0 && a[0].equals("--pure-only")) { pureOnly(a); return; }
        if (a.length > 0 && a[0].equals("--jdk-packages")) { jdkPackagesOut(a); return; }
        Path out = Path.of(a[0]), witness = Path.of(a[1]);
        hedgeOut = System.getProperty("framework.hedgeOut");
        List<String> header = Files.readAllLines(Path.of(a[2]), StandardCharsets.UTF_8);
        List<String[]> pairs = new ArrayList<>();
        for (int i = 3; i + 1 < a.length; i += 2) pairs.add(new String[] { a[i], a[i + 1] });
        pairs.sort(Comparator.comparing(p -> Path.of(p[0]).getFileName().toString()));
        loadUniverse(pairs);
        int N = nodeKey.size();
        computePure();
        // 3. direct effects from the engine's own scan
        int[] eff = new int[N];
        int[][] ptr = new int[N][];
        for (int j = 0; j < pairs.size(); j++) {
            JsonObject r;
            try (Reader rd = Files.newBufferedReader(Path.of(pairs.get(j)[1]), StandardCharsets.UTF_8)) {
                r = JsonParser.parseReader(rd).getAsJsonObject();
            }
            for (JsonElement fe : r.getAsJsonArray("functions")) {
                JsonObject f = fe.getAsJsonObject();
                if (!f.has("hash") || !f.has("direct")) continue;
                if (f.has("inferred")) {
                    JsonArray inf = f.getAsJsonArray("inferred");
                    if (inf.size() == 1 && inf.get(0).getAsString().equals("Unknown")) {
                        Integer uid = nodeId.get(j + "|" + f.get("hash").getAsString());
                        if (uid != null) UNK_ONLY.add(uid);
                    }
                }
                int mask = 0;
                for (JsonElement d : f.getAsJsonArray("direct")) mask |= bit(d.getAsString());
                if (mask == 0) continue;
                String h = f.get("hash").getAsString();
                Integer id = nodeId.get(j + "|" + h);
                if (id == null) continue;
                eff[id] |= mask;
            }
        }
        for (int n = 0; n < N; n++) if (eff[n] != 0) { ptr[n] = new int[CONC.length]; Arrays.fill(ptr[n], n); }
        // 4. statically-resolved edges -> reverse adjacency
        List<int[]> preds = new ArrayList<>(N);
        int[][] succ = new int[N][];
        int[] pc = new int[N];
        for (int n = 0; n < N; n++) {
            TreeSet<Integer> s = new TreeSet<>(successors(n));
            s.remove(n);
            int[] arr = new int[s.size()];
            int i = 0;
            for (int x : s) { arr[i++] = x; pc[x]++; }
            succ[n] = arr;
        }
        int[][] pred = new int[N][];
        for (int n = 0; n < N; n++) pred[n] = new int[pc[n]];
        int[] fill = new int[N];
        for (int n = 0; n < N; n++) for (int x : succ[n]) pred[x][fill[x]++] = n;
        // 5. least fixpoint, deterministic worklist; ptr[n][e] = the successor that first supplied e
        ArrayDeque<Integer> wl = new ArrayDeque<>();
        boolean[] inWl = new boolean[N];
        for (int n = 0; n < N; n++) if (eff[n] != 0) { wl.add(n); inWl[n] = true; }
        while (!wl.isEmpty()) {
            int n = wl.poll();
            inWl[n] = false;
            for (int p : pred[n]) {
                int add = eff[n] & ~eff[p];
                if (add == 0) continue;
                if (ptr[p] == null) { ptr[p] = new int[CONC.length]; Arrays.fill(ptr[p], -1); }
                for (int i = 0; i < CONC.length; i++) if ((add & (1 << i)) != 0) ptr[p][i] = n;
                eff[p] |= add;
                if (!inWl[p]) { wl.add(p); inWl[p] = true; }
            }
        }
        // 5a. SOUNDNESS R1052 — A P LINE IS HONOURED INSIDE A LIBRARY BODY ONLY WHERE THE TABLE CAN SEE THE WHOLE CLOSURE.
        // The scans dropped the name rule at every call to a P member. Where a body ALSO reaches a dispatch the table
        // cannot follow (an abstract member with an effectful or unknown implementer, or an unsurveyed owner, that no
        // rule charges), that dropped charge was the only thing standing in for the hidden one. MEASURED:
        // RabbitMessagingTemplate.receiveAndConvert(Class) reached the broker through the ABSTRACT doReceive, and its
        // only table charge was the blanket on its own resolveDestination() — a P member. Dropped, the row vanished,
        // RabbitMessageOperations.receiveAndConvert lost its `A` hedge, and a consumer's call read silent. So for a body
        // whose closure is OPAQUE, the rule's charge on every P call it reaches is put back; a FOLLOWABLE closure keeps
        // the drop, because there the table's own answer is complete.
        String pin0 = System.getProperty("framework.pureIn");
        Set<String> pureKeys = new HashSet<>(PURE);
        if (pin0 != null) pureKeys.retainAll(Files.readAllLines(Path.of(pin0), StandardCharsets.UTF_8));
        int[] dropC = new int[N];
        boolean[] opaqueC = new boolean[N];
        for (int n = 0; n < N; n++) {
            MethodNode mn = nodeMethod.get(n);
            if (mn.instructions == null) continue;
            for (AbstractInsnNode in : mn.instructions) {
                if (!(in instanceof MethodInsnNode m) || m.owner.startsWith("[")) continue;
                if (pureKeys.contains(m.owner + "." + m.name + m.desc)) dropC[n] |= ruleMask(m.owner, m.name, m.desc);
                else if (!jdkOwner(m.owner) && !loggingFrontier(m.owner) && !runtimeOwner(m.owner)
                        && !ruleCharges(m.owner, m.name, m.desc) && resolve(nodeJar.get(n), m.owner, m.name, m.desc).isEmpty()
                        && (!classJars.containsKey(m.owner) || implementersUnvouched(m.owner, m.name, m.desc, eff)))
                    opaqueC[n] = true;
            }
        }
        {   // close both over the same statically-resolved edges, callers inherit from callees
            ArrayDeque<Integer> q = new ArrayDeque<>();
            boolean[] inq = new boolean[N];
            for (int n = 0; n < N; n++) if (dropC[n] != 0 || opaqueC[n]) { q.add(n); inq[n] = true; }
            while (!q.isEmpty()) {
                int n = q.poll(); inq[n] = false;
                for (int p : pred[n]) {
                    int nd = dropC[p] | dropC[n];
                    boolean no = opaqueC[p] || opaqueC[n];
                    if (nd != dropC[p] || no != opaqueC[p]) { dropC[p] = nd; opaqueC[p] = no; if (!inq[p]) { q.add(p); inq[p] = true; } }
                }
            }
        }
        int reapplied = 0;
        for (int n = 0; n < N; n++) if (opaqueC[n] && (dropC[n] & ~eff[n]) != 0) { eff[n] |= dropC[n]; reapplied++; }
        System.err.println("framework-reach: " + reapplied + " bodies keep a P member's rule charge (opaque closure)");
        // 5b. SOUNDNESS R1052 — the P list for the NEXT iteration: this run's candidates, restricted to the list the
        // scans were given (-Dframework.pureIn), whose return type is inert under these closed effects. derive.sh
        // stops when it reproduces its input.
        EFF = eff;
        TreeSet<String> pureIn = new TreeSet<>(PURE);
        String pin = System.getProperty("framework.pureIn");
        if (pin != null) pureIn.retainAll(Files.readAllLines(Path.of(pin), StandardCharsets.UTF_8));
        TreeSet<String> pureNext = new TreeSet<>();
        for (String k : pureIn) {
            String desc = k.substring(k.indexOf('('));
            if (returnTypeInert(Type.getReturnType(desc), PURE_JAR.get(k))) pureNext.add(k);
        }
        String pout = System.getProperty("framework.pureOut");
        if (pout != null) {
            StringBuilder pb = new StringBuilder();
            for (String k : pureNext) pb.append(k).append('\n');
            Files.writeString(Path.of(pout), pb.toString(), StandardCharsets.UTF_8);
        }
        PURE.clear(); PURE.addAll(pureIn);          // the hedge's P lines are the list the scans used
        // 6. entries: every consumer-callable member of every public class under a covered prefix
        TreeMap<String, TreeMap<Integer, Integer>> perJar = new TreeMap<>();   // key -> jar -> mask
        TreeMap<String, TreeMap<Integer, int[]>> roots = new TreeMap<>();      // key -> jar -> resolved roots
        for (int j = 0; j < jarClasses.size(); j++) {
            for (ClassNode cn : jarClasses.get(j).values()) {
                if ((cn.access & Opcodes.ACC_PUBLIC) == 0 || (cn.access & Opcodes.ACC_SYNTHETIC) != 0) continue;
                int sl = cn.name.lastIndexOf('/');
                if (sl <= 0 || !Candor.kappaCovers(cn.name.substring(0, sl).replace('/', '.')) || loggingFrontier(cn.name)) continue;
                boolean framework = !runtimeOwner(cn.name);
                if (framework) SURVEYED.add(cn.name);
                for (String sig : visibleSignatures(j, cn)) {
                    int p = sig.indexOf('(');
                    String name = sig.substring(0, p), desc = sig.substring(p);
                    List<Integer> tg = resolve(j, cn.name, name, desc);
                    if (framework && !name.equals("<clinit>")) {
                        if (tg.isEmpty()) { if (!name.equals("<init>") && implementersUnvouched(cn.name, name, desc, eff))
                            HEDGE.putIfAbsent(cn.name + "." + sig, "A"); }
                        else if (UNK_ONLY.containsAll(tg)) HEDGE.putIfAbsent(cn.name + "." + sig, "U");
                    }
                    if (tg.isEmpty()) continue;
                    MethodNode decl = nodeMethod.get(tg.get(0));
                    boolean callable = (decl.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0;
                    if (!callable || name.equals("<clinit>")) continue;
                    LinkedHashSet<Integer> rs = new LinkedHashSet<>(tg);
                    if ((decl.access & Opcodes.ACC_STATIC) != 0 || name.equals("<init>")) rs.addAll(clinits(j, cn.name));
                    int mask = 0;
                    for (int r : rs) mask |= eff[r];
                    String key = cn.name + "." + sig;
                    perJar.computeIfAbsent(key, k -> new TreeMap<>()).put(j, mask);
                    roots.computeIfAbsent(key, k -> new TreeMap<>()).put(j, rs.stream().mapToInt(Integer::intValue).toArray());
                }
            }
        }
        // 7. emit
        List<String> rows = new ArrayList<>();
        List<String> wit = new ArrayList<>();
        for (Map.Entry<String, TreeMap<Integer, Integer>> e : perJar.entrySet()) {
            String key = e.getKey();
            int inter = -1, union = 0;
            for (int m : e.getValue().values()) { inter &= m; union |= m; }
            if (union == 0) continue;
            if (inter != union) {
                StringJoiner sj = new StringJoiner(" ");
                for (Map.Entry<Integer, Integer> pj : e.getValue().entrySet()) sj.add(jarNames.get(pj.getKey()) + "=" + names(pj.getValue()));
                wit.add(key + "\t" + names(union & ~inter) + "\tDIVERGENT\t" + sj);
            }
            if (inter == 0) continue;
            rows.add(key + "\t" + names(inter));
            for (int i = 0; i < CONC.length; i++) {
                if ((inter & (1 << i)) == 0) continue;
                int j = e.getValue().firstKey();
                int start = -1;
                for (int r : roots.get(key).get(j)) if ((eff[r] & (1 << i)) != 0) { start = r; break; }
                StringJoiner path = new StringJoiner(" > ");
                int cur = start, guard = 0;
                if (start < 0) path.add("(no single body: re-applied rule charge, R1052 5a)");
                while (cur >= 0 && guard++ < 10_000) {
                    path.add(nodeKey.get(cur));
                    if (ptr[cur] == null || ptr[cur][i] < 0) { path.add("(R1052 5a: a P member's rule charge kept — opaque closure)"); break; }
                    int nx = ptr[cur][i];
                    if (nx == cur) break;
                    cur = nx;
                }
                wit.add(key + "\t" + CONC[i].specName() + "\t" + jarNames.get(j) + "\t" + path);
            }
        }
        if (hedgeOut != null) {
            java.util.Set<String> charged = new HashSet<>();
            for (String r : rows) charged.add(r.substring(0, r.indexOf('\t')));
            List<String> hl = new ArrayList<>();
            for (String pk : jdkPackages()) if (Candor.kappaCovers(pk)) hl.add("J\t" + pk);
            for (String c : SURVEYED) hl.add("S\t" + c);
            for (Map.Entry<String, String> h : HEDGE.entrySet())
                if (!charged.contains(h.getKey())) hl.add(h.getValue() + "\t" + h.getKey());
            for (String pk : PURE) hl.add("P\t" + pk);
            Collections.sort(hl);
            MessageDigest hm = MessageDigest.getInstance("SHA-256");
            for (String r : hl) hm.update((r + "\n").getBytes(StandardCharsets.UTF_8));
            StringBuilder hb = new StringBuilder();
            for (String h : header) hb.append(h).append('\n');
            hb.append("# hedge: J = a JDK package (runtime), S = a surveyed framework class, A/U = a framework member the\n");
            hb.append("# table cannot vouch for (A: no body — dispatch; U: the scan read it only as Unknown). See FrameworkReach.\n");
            hb.append("# P = a member a NAME rule charges whose surveyed body is a proven-pure field accessor (R1052).\n");
            hb.append("# entries ").append(hl.size()).append('\n');
            hb.append("# content-sha256 ").append(HexFormat.of().formatHex(hm.digest())).append('\n');
            for (String r : hl) hb.append(r).append('\n');
            Files.writeString(Path.of(hedgeOut), hb.toString(), StandardCharsets.UTF_8);
        }
        Collections.sort(rows);
        Collections.sort(wit);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (String r : rows) md.update((r + "\n").getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (String h : header) sb.append(h).append('\n');
        sb.append("# entries ").append(rows.size()).append('\n');
        sb.append("# content-sha256 ").append(HexFormat.of().formatHex(md.digest())).append('\n');
        for (String r : rows) sb.append(r).append('\n');
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
        StringBuilder wb = new StringBuilder();
        for (String w : wit) wb.append(w).append('\n');
        Files.writeString(witness, wb.toString(), StandardCharsets.UTF_8);
        System.err.println("framework-reach: " + N + " bodies, " + perJar.size() + " callable members, "
                + rows.size() + " charged rows");
    }


    // ── SOUNDNESS R1052(b,c) — RULE-CHARGED MEMBERS WHOSE BODY IS A PROVEN-PURE ACCESSOR ─────────────────────────
    /** {@code P} lines: a member a NAME rule charges — the model-SDK blanket ({@link Rules#isModelSdkOwner}) or an
     *  OWNER-BLANKET classifier rule ({@link Candor#isOwnerBlanketRule}) — whose resolved body, and everything it can
     *  run, was READ here and does nothing. Such a rule is a summary of a body nobody read; for these members the
     *  body was read. Measured instances: Spring AI {@code Prompt.getOptions()} ({@code aload_0; getfield; areturn})
     *  charged {@code Llm,Net} at every call; spring-web {@code RestTemplate.validateConverters} (two
     *  {@code Assert} checks) charged {@code Net} inside every RestTemplate constructor.
     *
     *  <p>PROVEN, NOT ASSUMED — this is a purity claim, so every gap answers "not pure" and keeps the rule. A body is
     *  pure when every instruction is one of: a field/array/stack/arith/branch/throw op; a call to a surveyed body that
     *  is itself pure (STATICALLY RESOLVED, as the table's own edges are — never an abstract/interface member, never
     *  an unsurveyed or logging-frontier owner); or a JDK call on {@link #safeJdk}'s ALLOWLIST (the safe direction for
     *  a purity claim: a member missing from it keeps the rule). A NEW or static access to a surveyed class also
     *  needs that class's {@code <clinit>} chain pure; to an unsurveyed non-JDK class it disqualifies. No lambdas or
     *  method references; string concatenation only over strings and primitives (an object operand calls its
     *  {@code toString}). The residual is the table's own: the claim is about the body the JVM resolves in the
     *  SURVEYED version, never an override shipped in another jar. */
    static final TreeSet<String> PURE = new TreeSet<>();
    static final Map<String, Integer> PURE_JAR = new HashMap<>();
    static boolean[] pureNode;
    /** The closed effect masks of the main run, read by {@link #returnTypeInert}. */
    static int[] EFF;

    static void pureOnly(String[] a) throws Exception {
        List<String[]> pairs = new ArrayList<>();
        for (int i = 2; i < a.length; i++) pairs.add(new String[] { a[i], null });
        pairs.sort(Comparator.comparing(p -> Path.of(p[0]).getFileName().toString()));
        loadUniverse(pairs);
        computePure();
        StringBuilder sb = new StringBuilder();
        for (String k : PURE) sb.append(k).append('\n');
        Files.writeString(Path.of(a[1]), sb.toString(), StandardCharsets.UTF_8);
        System.err.println("framework-reach: " + PURE.size() + " proven-pure rule-charged members");
    }

    static Set<String> JDK_PKG_SET;

    static boolean jdkOwner(String internal) {
        if (JDK_PKG_SET == null) JDK_PKG_SET = new HashSet<>(jdkPackages());
        int sl = internal.lastIndexOf('/');
        return sl > 0 && JDK_PKG_SET.contains(internal.substring(0, sl).replace('/', '.'));
    }

    /** The JDK members a pure body may call: an ALLOWLIST of owners whose members neither perform an effect nor call
     *  back into code handed to them, further gated on the classifier (and R814's JDK sinks) charging nothing. Members
     *  taking an {@code Object}/functional parameter are refused unless they cannot invoke it (requireNonNull, list
     *  ADD — which, unlike a hash-set add or a map put, never calls {@code equals}/{@code hashCode}). */
    static boolean safeJdk(String owner, String name, String desc) {
        String dotted = owner.replace('/', '.');
        if (Classifier.classify(dotted, name, desc) != null) return false;
        if (KappaJdkSinks.charge(dotted, name, desc) != null || !KappaJdkSinks.alsoCharges(dotted, name, desc).isEmpty()) return false;
        boolean ownerOk = switch (owner) {
            case "java/lang/Object" -> name.equals("<init>") || name.equals("getClass");
            case "java/lang/String", "java/lang/StringBuilder", "java/lang/Integer", "java/lang/Long", "java/lang/Boolean",
                 "java/lang/Double", "java/lang/Float", "java/lang/Short", "java/lang/Byte", "java/lang/Character",
                 "java/lang/Math", "java/lang/Number", "java/lang/Enum",
                 "java/util/Objects", "java/util/Optional", "java/util/Collections", "java/util/Arrays",
                 "java/util/List", "java/util/ArrayList", "java/util/LinkedList", "java/util/Collection",
                 "java/util/Iterator", "java/util/ListIterator", "java/util/Set", "java/util/Map",
                 "java/util/HashMap", "java/util/LinkedHashMap", "java/util/HashSet", "java/util/LinkedHashSet",
                 "java/util/Map$Entry", "java/util/EnumMap", "java/util/EnumSet", "java/util/concurrent/ConcurrentHashMap",
                 "java/util/regex/Pattern", "java/util/regex/Matcher" -> true;
            default -> name.equals("<init>") && (owner.endsWith("Exception") || owner.endsWith("Error"))
                    && owner.startsWith("java/lang/");
        };
        if (!ownerOk) return false;
        if (owner.equals("java/lang/String") && (name.equals("format") || name.equals("formatted"))) return false;
        // a call that can run code it was handed, or a contract method (toString/equals/hashCode/compareTo) of an
        // argument whose type nobody here knows
        for (Type t : Type.getArgumentTypes(desc)) {
            if (t.getSort() == Type.ARRAY) t = t.getElementType();
            if (t.getSort() != Type.OBJECT) continue;
            String n = t.getInternalName();
            if (n.equals("java/lang/String") || n.equals("java/lang/Integer") || n.equals("java/lang/Long")
                    || n.equals("java/lang/Boolean") || n.equals("java/lang/CharSequence")) continue;
            boolean cannotInvoke = (owner.equals("java/util/Objects") && name.startsWith("requireNonNull") && !desc.contains("Ljava/util/function/"))
                    || ((name.equals("add") || name.equals("addAll") || name.equals("set") || name.equals("<init>"))
                        && (owner.equals("java/util/List") || owner.equals("java/util/ArrayList")
                            || owner.equals("java/util/LinkedList") || owner.equals("java/util/Collection")))
                    || (owner.equals("java/util/Optional") && (name.equals("of") || name.equals("ofNullable")))
                    || (owner.equals("java/util/Collections") && name.startsWith("unmodifiable"))
                    || (owner.equals("java/util/Arrays") && name.equals("asList"))
                    || (owner.equals("java/util/Collection") && name.equals("toArray"))
                    || (owner.equals("java/util/List") && name.equals("toArray"));
            if (!cannotInvoke) return false;
        }
        return true;
    }

    static void computePure() {
        int N = nodeKey.size();
        pureNode = new boolean[N];
        Arrays.fill(pureNode, true);
        // local pass: instructions that are never pure, whatever they call
        List<List<Integer>> deps = new ArrayList<>(N);
        for (int n = 0; n < N; n++) {
            List<Integer> d = new ArrayList<>();
            if (!localPure(n, d)) pureNode[n] = false;
            deps.add(d);
        }
        // greatest fixpoint: a body is pure only while every body it can run is
        boolean changed = true;
        while (changed) {
            changed = false;
            for (int n = 0; n < N; n++) {
                if (!pureNode[n]) continue;
                for (int t : deps.get(n)) if (t < 0 || !pureNode[t]) { pureNode[n] = false; changed = true; break; }
            }
        }
        for (int j = 0; j < jarClasses.size(); j++) {
            for (ClassNode cn : jarClasses.get(j).values()) {
                int sl = cn.name.lastIndexOf('/');
                if (sl <= 0 || (cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
                String dotted = cn.name.replace('/', '.');
                if (!Candor.kappaCovers(cn.name.substring(0, sl).replace('/', '.')) || runtimeOwner(cn.name)) continue;
                Set<String> sigs = new TreeSet<>(visibleSignatures(j, cn));
                for (MethodNode mn : cn.methods) if ((mn.access & Opcodes.ACC_PRIVATE) != 0) sigs.add(mn.name + mn.desc);
                for (String sig : sigs) {
                    int p = sig.indexOf('(');
                    String name = sig.substring(0, p), desc = sig.substring(p);
                    if (name.equals("<clinit>")) continue;
                    boolean ruled = (Rules.isModelSdkOwner(dotted) && !name.equals("<init>") && !Rules.isSpringAiPureBuilder(dotted, name))
                            || (Classifier.classify(dotted, name, desc) != null && Candor.isOwnerBlanketRule(dotted, desc));
                    if (!ruled) continue;
                    List<Integer> tg = resolve(j, cn.name, name, desc);
                    if (tg.isEmpty()) continue;
                    boolean all = true;
                    for (int t : tg) if (!pureNode[t]) { all = false; break; }
                    // a static member or a constructor also runs the class initialiser chain (JVMS 5.5) — except a
                    // PRIVATE static, which only the class itself can call, after its initialiser has run
                    MethodNode decl = nodeMethod.get(tg.get(0));
                    boolean privateStatic = (decl.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE))
                            == (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE);
                    if (all && !privateStatic && ((decl.access & Opcodes.ACC_STATIC) != 0 || name.equals("<init>")))
                        for (int c : clinits(j, cn.name)) if (!pureNode[c]) { all = false; break; }
                    if (all) { PURE.add(cn.name + "." + sig); PURE_JAR.putIfAbsent(cn.name + "." + sig, j); }
                }
            }
        }
    }

    static final Map<String, Boolean> INERT = new HashMap<>();

    /** Whether a value of type {@code t} cannot carry I/O to a later call that only the factory's blanket charged: a
     *  primitive, a JDK VALUE or collection type (java.lang / java.util — not java.util.concurrent or java.util.stream,
     *  whose futures and streams run deferred work — java.time, java.math, java.net.URI), or a SURVEYED framework type
     *  none of whose ABSTRACT members a consumer can call is one the hedge discloses as `dispatch:` (an implementer the
     *  table charges or could read only as Unknown, or none — {@link #implementersUnvouched}, the A-line rule itself).
     *  Measured reason: MongoTemplate.query(X.class) is pure, and the Db is `.all()` on the ExecutableFind INTERFACE it
     *  returns, hedged `dispatch:` — so dropping the blanket on query() turned `deny Db` 1 -> 0 behind an Unknown. A
     *  CONCRETE member is answered at the consumer by the table from its own body, and an abstract member a NAME rule
     *  charges at the consumer's own call (Spring AI's {@code ChatOptions.copy()} under the model-SDK blanket) keeps
     *  that charge — neither can lose its label this way. One level deep; anything unsurveyed is not inert. Needs the closed effect masks, which is why derive.sh
     *  iterates the P list to a fixed point (fewer P lines -> more charges -> fewer inert types, so it only shrinks). */
    static boolean returnTypeInert(Type t, int j) {
        if (t.getSort() == Type.ARRAY) t = t.getElementType();
        if (t.getSort() != Type.OBJECT) return true;
        String n = t.getInternalName();
        if (jdkOwner(n)) return (n.startsWith("java/lang/") && !n.startsWith("java/lang/reflect/") && !n.startsWith("java/lang/invoke/")
                        && !n.equals("java/lang/Thread") && !n.equals("java/lang/Process") && !n.equals("java/lang/ClassLoader")
                        && !n.equals("java/lang/Runnable") && !n.equals("java/lang/AutoCloseable") && !n.equals("java/lang/Readable")
                        && !n.equals("java/lang/Appendable"))
                || (n.startsWith("java/util/") && !n.startsWith("java/util/concurrent/") && !n.startsWith("java/util/stream/")
                        && !n.startsWith("java/util/function/") && !n.startsWith("java/util/logging/") && !n.startsWith("java/util/jar/")
                        && !n.startsWith("java/util/zip/") && !n.equals("java/util/Scanner") && !n.equals("java/util/Timer"))
                || n.startsWith("java/time/") || n.startsWith("java/math/") || n.equals("java/net/URI");
        Boolean m = INERT.get(n);
        if (m != null) return m;
        INERT.put(n, false);                        // a cycle is not a proof
        int cj = jarOf(j, n);
        ClassNode c = cls(cj, n);
        boolean r = c != null && !loggingFrontier(n) && !runtimeOwner(n);
        if (r) {
            for (String sig : visibleSignatures(cj, c)) {
                int p = sig.indexOf('(');
                String name = sig.substring(0, p), desc = sig.substring(p);
                if (name.equals("<init>") || name.equals("<clinit>")) continue;
                List<Integer> tg = resolve(cj, n, name, desc);
                // A CONCRETE member is answered at the consumer by its own body — the table charges what it reaches —
                // so it cannot lose its label to this. An ABSTRACT one is where the factory's blanket was the only
                // concrete charge the chain carried (the consumer otherwise gets a `dispatch:` Unknown), so it must be
                // pure through every surveyed implementer.
                if (tg.isEmpty() && implementersUnvouched(n, name, desc, EFF) && !ruleCharges(n, name, desc)) r = false;
                if (!r) break;
            }
        }
        INERT.put(n, r);
        return r;
    }

    /** The effects the NAME rule(s) a P line overrides would charge at a call to {@code owner.name+desc}. */
    static int ruleMask(String owner, String name, String desc) {
        String dotted = owner.replace('/', '.');
        int m = 0;
        Effect e = Classifier.classify(dotted, name, desc);
        if (e != null && e != Effect.UNKNOWN) m |= bit(e.specName());
        if (Rules.isModelSdkOwner(dotted) && !name.equals("<init>") && !Rules.isSpringAiPureBuilder(dotted, name))
            m |= bit(Effect.LLM.specName()) | bit(Effect.NET.specName());
        return m;
    }

    /** Whether a consumer's own call to {@code owner.name+desc} is charged by a NAME rule (classifier or model-SDK
     *  blanket) — the charge an abstract member keeps regardless of what the factory that produced its receiver got. */
    static boolean ruleCharges(String owner, String name, String desc) {
        String dotted = owner.replace('/', '.');
        return Classifier.classify(dotted, name, desc) != null
                || (Rules.isModelSdkOwner(dotted) && !name.equals("<init>") && !Rules.isSpringAiPureBuilder(dotted, name));
    }

    /** The per-instruction half of the purity proof; {@code deps} receives every body this one can run (-1 = one
     *  that cannot be proven, which fails the fixpoint). */
    static boolean localPure(int n, List<Integer> deps) {
        MethodNode mn = nodeMethod.get(n);
        if (mn.instructions == null || (mn.access & Opcodes.ACC_SYNCHRONIZED) != 0) return false;
        int j = nodeJar.get(n);
        for (AbstractInsnNode in : mn.instructions) {
            int op = in.getOpcode();
            if (op < 0) continue;
            if (op == Opcodes.MONITORENTER || op == Opcodes.MONITOREXIT) return false;
            if (in instanceof InvokeDynamicInsnNode d) {
                if (d.bsm == null || !d.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) return false;
                for (Type t : Type.getArgumentTypes(d.desc))
                    if (t.getSort() == Type.OBJECT && !t.getInternalName().equals("java/lang/String")) return false;
                    else if (t.getSort() == Type.ARRAY) return false;
                continue;
            }
            if (in instanceof org.objectweb.asm.tree.LdcInsnNode l
                    && (l.cst instanceof Handle || l.cst instanceof org.objectweb.asm.ConstantDynamic)) return false;
            String touched = null;
            if (in instanceof org.objectweb.asm.tree.FieldInsnNode f && (op == Opcodes.GETSTATIC || op == Opcodes.PUTSTATIC)) touched = f.owner;
            if (in instanceof org.objectweb.asm.tree.TypeInsnNode t && op == Opcodes.NEW) touched = t.desc;
            if (in instanceof MethodInsnNode m) {
                if (m.owner.startsWith("[")) { if (!m.name.equals("clone")) return false; continue; }
                if (jdkOwner(m.owner)) { if (!safeJdk(m.owner, m.name, m.desc)) return false; continue; }
                if (loggingFrontier(m.owner) || runtimeOwner(m.owner)) return false;
                List<Integer> tg = resolve(j, m.owner, m.name, m.desc);
                if (tg.isEmpty()) return false;              // abstract, interface, native or unsurveyed: unproven
                deps.addAll(tg);
                if (op == Opcodes.INVOKESTATIC) touched = m.owner;
            }
            if (touched != null && !touched.equals(nodeOwner.get(n)) && !jdkOwner(touched)) {
                int cj = jarOf(j, touched);
                if (cj < 0 || loggingFrontier(touched) || runtimeOwner(touched)) return false;
                deps.addAll(clinits(cj, touched));
            } else if (touched != null && jdkOwner(touched) && op != Opcodes.NEW && !touched.startsWith("java/lang/")
                    && !touched.startsWith("java/util/")) return false;   // a JDK static field outside lang/util
        }
        return true;
    }

    static void loadUniverse(List<String[]> pairs) throws Exception {
        // 1. load classes
        for (String[] p : pairs) {
            int j = jarNames.size();
            jarNames.add(Path.of(p[0]).getFileName().toString());
            Map<String, ClassNode> m = new TreeMap<>();
            try (ZipFile z = new ZipFile(p[0])) {
                List<? extends ZipEntry> es = Collections.list(z.entries());
                es.sort(Comparator.comparing(ZipEntry::getName));
                for (ZipEntry e : es) {
                    String n = e.getName();
                    if (!n.endsWith(".class") || n.startsWith("META-INF/") || n.endsWith("module-info.class")
                            || n.endsWith("package-info.class")) continue;
                    ClassNode cn = new ClassNode();
                    try (InputStream in = z.getInputStream(e)) { new ClassReader(in).accept(cn, ClassReader.SKIP_FRAMES); }
                    catch (RuntimeException ex) { continue; }
                    m.putIfAbsent(cn.name, cn);
                }
            }
            jarClasses.add(m);
            for (String c : m.keySet()) classJars.computeIfAbsent(c, k -> new ArrayList<>()).add(j);
        }
        // 2. nodes
        List<String> keys = new ArrayList<>();
        for (int j = 0; j < jarClasses.size(); j++)
            for (ClassNode cn : jarClasses.get(j).values())
                for (MethodNode mn : cn.methods)
                    if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0)
                        keys.add(String.format("%04d", j) + "|" + cn.name + "." + mn.name + mn.desc);
        Collections.sort(keys);
        Map<String, MethodNode> byKey = new HashMap<>();
        for (int j = 0; j < jarClasses.size(); j++)
            for (ClassNode cn : jarClasses.get(j).values())
                for (MethodNode mn : cn.methods) byKey.put(j + "|" + cn.name + "." + mn.name + mn.desc, mn);
        for (String k : keys) {
            int bar = k.indexOf('|');
            int j = Integer.parseInt(k.substring(0, bar));
            String rest = k.substring(bar + 1);
            String owner = rest.substring(0, rest.lastIndexOf('.', rest.indexOf('(')));
            String id = j + "|" + rest;
            nodeId.put(id, nodeKey.size());
            nodeKey.add(rest);
            nodeMethod.add(byKey.get(id));
            nodeOwner.add(owner);
            nodeJar.add(j);
        }
    }

    /** The class {@code owner} as seen from jar {@code j}: its own copy first, else the first surveyed jar that has
     *  one (deterministic: jars are sorted). */
    static int jarOf(int j, String owner) {
        if (jarClasses.get(j).containsKey(owner)) return j;
        List<Integer> js = classJars.get(owner);
        return js == null ? -1 : js.get(0);
    }

    static ClassNode cls(int j, String owner) { return j < 0 ? null : jarClasses.get(j).get(owner); }

    /** JVMS 5.4.3.3/5.4.3.4 method resolution against the surveyed bodies only. Returns the resolved body's node, or
     *  every maximally-specific default when the class chain has none; empty when the chain leaves the surveyed
     *  jars (a JDK or unsurveyed body — the engine's own `direct` already classified that call) or resolves to an
     *  abstract/native declaration. */
    static List<Integer> resolve(int from, String owner, String name, String desc) {
        if (loggingFrontier(owner)) return List.of();
        String nd = name + desc;
        String c = owner;
        int j = jarOf(from, c);
        Set<String> seen = new HashSet<>();
        List<String[]> ifaceRoots = new ArrayList<>();
        while (c != null && j >= 0 && seen.add(c)) {
            ClassNode cn = cls(j, c);
            if (cn == null || loggingFrontier(c)) break;
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals(name) && mn.desc.equals(desc)) {
                    if ((mn.access & Opcodes.ACC_PRIVATE) != 0 && !c.equals(owner)) continue;   // not inherited
                    if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return List.of();
                    Integer id = node(j, c, nd);
                    return id == null ? List.of() : List.of(id);
                }
            }
            ifaceRoots.add(new String[] { String.valueOf(j), c });
            if (name.equals("<init>") || name.equals("<clinit>")) return List.of();
            String sup = cn.superName;
            if (sup == null) break;
            int sj = jarOf(j, sup);
            c = sup; j = sj;
        }
        // superinterface defaults
        List<Integer> out = new ArrayList<>();
        ArrayDeque<String[]> q = new ArrayDeque<>();
        Set<String> vis = new HashSet<>();
        for (String[] r : ifaceRoots) {
            ClassNode cn = cls(Integer.parseInt(r[0]), r[1]);
            if (cn != null) for (String i : cn.interfaces) q.add(new String[] { r[0], i });
        }
        while (!q.isEmpty()) {
            String[] x = q.poll();
            int ij = jarOf(Integer.parseInt(x[0]), x[1]);
            if (ij < 0 || !vis.add(x[1])) continue;
            ClassNode in = cls(ij, x[1]);
            if (in == null || loggingFrontier(x[1])) continue;
            boolean found = false;
            for (MethodNode mn : in.methods) {
                if (mn.name.equals(name) && mn.desc.equals(desc)
                        && (mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) == 0) {
                    Integer id = node(ij, x[1], nd);
                    if (id != null && !out.contains(id)) out.add(id);
                    found = true;
                }
            }
            if (!found) for (String i : in.interfaces) q.add(new String[] { String.valueOf(ij), i });
        }
        return out;
    }

    static Map<String, List<String>> subs;

    /** An abstract member is hedged unless EVERY surveyed implementation of it was examined and found pure. A
     *  member with no surveyed implementer at all (an API whose implementations ship elsewhere — a container, a
     *  driver) is hedged; one whose only implementers are pure bodies the table read (dbunit's
     *  {@code IDatabaseConnection.getSchema} returns a field in every implementation) is not. Project-side
     *  implementers are the consumer scan's own business — its CHA sees them. */
    static boolean implementersUnvouched(String owner, String name, String desc, int[] eff) {
        if (subs == null) {
            subs = new HashMap<>();
            for (Map<String, ClassNode> m : jarClasses)
                for (ClassNode c : m.values()) {
                    if (c.superName != null) subs.computeIfAbsent(c.superName, k -> new ArrayList<>()).add(c.name);
                    for (String i : c.interfaces) subs.computeIfAbsent(i, k -> new ArrayList<>()).add(c.name);
                }
        }
        ArrayDeque<String> q = new ArrayDeque<>(subs.getOrDefault(owner, List.of()));
        Set<String> seen = new HashSet<>();
        int bodies = 0;
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            q.addAll(subs.getOrDefault(c, List.of()));
            List<Integer> js = classJars.get(c);
            if (js == null) continue;
            for (int j : js) {
                ClassNode cn = cls(j, c);
                if (cn == null || (cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0) continue;
                for (int t : resolve(j, c, name, desc)) {
                    bodies++;
                    if (eff[t] != 0 || UNK_ONLY.contains(t)) return true;
                }
            }
        }
        return bodies == 0;
    }

    /** The {@code <clinit>} bodies initialising {@code owner} runs (its own, then its superclasses'). */
    static List<Integer> clinits(int from, String owner) {
        List<Integer> out = new ArrayList<>();
        String c = owner;
        int j = jarOf(from, c);
        Set<String> seen = new HashSet<>();
        while (c != null && j >= 0 && seen.add(c)) {
            ClassNode cn = cls(j, c);
            if (cn == null) break;
            Integer id = node(j, c, "<clinit>()V");
            if (id != null) out.add(id);
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) break;
            c = cn.superName;
            j = c == null ? -1 : jarOf(j, c);
        }
        return out;
    }

    /** The statically-resolved successors of a body: every call's resolved target and every lambda/method-reference
     *  implementation. NOT the {@code <clinit>} a {@code new}/static access inside the body would trigger — see the
     *  class comment: that edge is taken once, at the ENTRY (the class the consumer names), never transitively. */
    static List<Integer> successors(int n) {
        MethodNode mn = nodeMethod.get(n);
        int j = nodeJar.get(n);
        List<Integer> out = new ArrayList<>();
        if (mn.instructions == null) return out;
        for (AbstractInsnNode in : mn.instructions) {
            if (in instanceof MethodInsnNode m) {
                if (m.owner.startsWith("[")) continue;
                out.addAll(resolve(j, m.owner, m.name, m.desc));
            } else if (in instanceof InvokeDynamicInsnNode d && d.bsm != null
                    && d.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory") && d.bsmArgs.length > 1
                    && d.bsmArgs[1] instanceof Handle h) {
                out.addAll(resolve(j, h.getOwner(), h.getName(), h.getDesc()));
            }
        }
        return out;
    }

    /** Every name+desc a consumer can name on {@code cn}: its own non-private members and every non-private member
     *  inherited along the surveyed superclass chain and superinterfaces. Resolution then decides which body runs. */
    static Set<String> visibleSignatures(int j, ClassNode cn) {
        TreeSet<String> out = new TreeSet<>();
        ArrayDeque<String[]> q = new ArrayDeque<>();
        Set<String> vis = new HashSet<>();
        q.add(new String[] { String.valueOf(j), cn.name });
        boolean first = true;
        while (!q.isEmpty()) {
            String[] x = q.poll();
            int cj = jarOf(Integer.parseInt(x[0]), x[1]);
            if (cj < 0 || !vis.add(x[1])) continue;
            ClassNode c = cls(cj, x[1]);
            if (c == null) continue;
            for (MethodNode mn : c.methods) {
                if ((mn.access & Opcodes.ACC_PRIVATE) != 0 || mn.name.equals("<clinit>")) continue;
                if (!first && mn.name.equals("<init>")) continue;
                out.add(mn.name + mn.desc);
            }
            first = false;
            if (c.superName != null) q.add(new String[] { String.valueOf(cj), c.superName });
            for (String i : c.interfaces) q.add(new String[] { String.valueOf(cj), i });
        }
        return out;
    }
}
