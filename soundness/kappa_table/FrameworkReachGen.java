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
    /** Bodies whose scan `inferred` carries {@code Unknown} at all (alone or beside concrete effects). */
    static final Set<Integer> UNK_ANY = new HashSet<>();
    /** SOUNDNESS R1189 — THE FLOOR: every member the PREVIOUS (checked-in) tables had a line for. A regeneration never
     *  drops such a member to "no line" (which a consumer reads as examined-and-pure) while every body it resolves to
     *  still carries {@code Unknown} in the scan: it keeps at least a {@code U} line. Measured: the R1188/R1189 engine
     *  resolved spring-core's {@code OrderComparator.sort} from {@code [Unknown]} to {@code [Fs, Log, Unknown]} through a
     *  comparator edge this closure cannot follow, and without the floor its U line vanished and a consumer read it pure. */
    static final Set<String> FLOOR = new HashSet<>();
    /** SOUNDNESS R1193 — and, beside the floor, every member whose resolved bodies all carry {@code Unknown} in the scan
     *  while this table's closure reaches no concrete effect from any of them: before R1193 such a member had no line in
     *  either table, which a consumer reads as examined-and-pure (jackson {@code ObjectMapper.treeToValue}: its own scan
     *  reads [Fs, Log, Unknown], a consumer read it pure). A disclosure only — never a charge.
     *  Floor candidates; a U line is written for one only where it would otherwise have NO line at all (not charged,
     *  no hedge, no broad-dispatch A) — the floor never adds a disclosure beside a line the member already has. */
    static final TreeSet<String> FLOORED = new TreeSet<>();
    static int floored = 0;
    /** Framework members a consumer can call whose body the table cannot vouch for: "A" — resolution reaches no
     *  body (abstract/interface/native: the implementer is chosen at run time); "U" — every resolved body is one the
     *  scan could read only as Unknown. Absent here and absent from the table = examined and pure. */
    static final TreeMap<String, String> HEDGE = new TreeMap<>();
    static final TreeSet<String> SURVEYED = new TreeSet<>();

    /** SOUNDNESS R1471 -- whether a body carries Unknown anywhere the scan could say so. The engine reports no row for a
     *  compiler-generated BRIDGE (covariant return, generic erasure), so a bridge reads as examined-and-pure even when
     *  the real body it forwards to is Unknown: mongodb's {@code Replacement.toDocumentExpression(..)Object} resolves, in
     *  its implementers, to the bridge, and the Document-returning body behind it reads [Db, Log, Unknown]. A bridge
     *  therefore carries what its (bridge-only chain of) callees carry. */
    static boolean unkAny(int t) { return unkAny(t, new HashSet<>()); }
    static boolean unkAny(int t, Set<Integer> seen) {
        if (UNK_ANY.contains(t)) return true;
        MethodNode m = nodeMethod.get(t);
        if (m == null || (m.access & Opcodes.ACC_BRIDGE) == 0 || !seen.add(t)) return false;
        for (int x : successors(t)) if (x != t && unkAny(x, seen)) return true;
        return false;
    }

    /** SOUNDNESS R1509 -- THE SURVEYED HIERARCHY, for a consumer that extends a framework class. {@link #implementersUnvouched}
     *  drops an abstract member's `A` line when every SURVEYED implementer is pure, on the premise that "project-side
     *  implementers are the consumer scan's own business -- its CHA sees them". It does not: a consumer
     *  {@code BadPeriod extends org.joda.time.base.BasePeriod} implements {@code ReadablePeriod} only through
     *  {@code BasePeriod}, whose bytes are not on the consumer scan's class path, so the consumer's CHA over
     *  {@code ReadablePeriod} is empty and {@code p.hashCode()} read silent over a body that reads a file (EXECUTED). These
     *  lines give the consumer the one fact it lacks: each surveyed class's direct supertypes, so it can walk from its own
     *  class, through the framework, to the dispatched type (Cha#crossBoundaryTargets). Every class in a covered package
     *  that has a supertype other than Object, from every surveyed jar (a class two versions declare with different
     *  supertypes gets their union -- a wider walk only adds candidates), JDK packages excluded (the engine reads those off
     *  its own class path). */
    static List<String> hierarchyLines() {
        List<String> out = new ArrayList<>(hierarchy().size());
        for (Map.Entry<String, LinkedHashSet<String>> e : hierarchy().entrySet())
            out.add("H\t" + e.getKey() + "\t" + String.join(",", e.getValue()));
        return out;
    }

    static TreeMap<String, LinkedHashSet<String>> HIER;

    /** The H lines' content: class -> direct supertypes, exactly as written (so the consumer's walk over them and
     *  {@link #templateLines}' suppression read the same first entry). */
    static TreeMap<String, LinkedHashSet<String>> hierarchy() {
        if (HIER != null) return HIER;
        Set<String> jdk = new HashSet<>(jdkPackages());
        TreeMap<String, LinkedHashSet<String>> sup = new TreeMap<>();
        for (Map<String, ClassNode> m : jarClasses)
            for (ClassNode cn : m.values()) {
                int sl = cn.name.lastIndexOf('/');
                if (sl <= 0) continue;
                String pkg = cn.name.substring(0, sl).replace('/', '.');
                if (!Candor.kappaCovers(pkg) || jdk.contains(pkg) || (cn.access & Opcodes.ACC_SYNTHETIC) != 0) continue;
                List<String> s = new ArrayList<>();
                if (cn.superName != null && !cn.superName.equals("java/lang/Object")) s.add(cn.superName);
                s.addAll(cn.interfaces);
                if (s.isEmpty()) continue;
                sup.computeIfAbsent(cn.name, k -> new LinkedHashSet<>()).addAll(s);
            }
        HIER = sup;
        return sup;
    }

    // ── SOUNDNESS R1511 — A TEMPLATE METHOD CALLS BACK AN OVERRIDE ON ITS OWN RECEIVER ─────────────────────────────────
    /** key (a subclassable surveyed class . member) -> the overridable members its body runs on {@code this}. */
    static final TreeMap<String, TreeSet<String>> TEMPLATE = new TreeMap<>();
    static final Map<Integer, List<Object[]>> THIS_CALLS = new HashMap<>();

    /** SOUNDNESS R1511 -- the members a consumer subclass of {@code cls} can override that the body(ies) {@code roots}
     *  dispatch on their OWN receiver, closed over the bodies those calls run on that receiver. A consumer
     *  {@code CbPeriod extends BasePeriod} overriding {@code getValue(int)} with a file read is called back by the
     *  inherited {@code AbstractPeriod.hashCode} (EXECUTED: 8 reads), and the consumer scan, which has no framework
     *  bytes, cannot see that call: it reads {@code p.hashCode()} as the table's pure row. These lines give it the
     *  one fact it lacks; Cha#templateCallbacks joins the consumer's own overrides of the members named.
     *
     *  <p>Only calls whose receiver is {@code this} (an {@code ALOAD 0} in an instance body that never stores local
     *  0): a call on another object runs that object's override, which a CHA over every consumer override would
     *  smear onto every caller (the R1509 smear). A virtual call is resolved from {@code cls} -- the receiver is at
     *  least a {@code cls} -- and followed; a {@code super}/private/constructor call ({@code INVOKESPECIAL}) runs
     *  exactly its owner's body on the same receiver and is followed without being recorded. A member is recorded
     *  unless its nearest surveyed declaration from {@code cls} is final, static, private or package-private (none
     *  of which a consumer in another package can override); a declaration outside the survey (the JDK) is
     *  recorded, and the consumer joins only a body its own class declares with that exact name and descriptor. */
    /** SOUNDNESS R1511 -- the T lines, compressed two ways, both exact. (1) A key whose list equals what the consumer's
     *  walk reads one class up is not written: FrameworkReach#templateMembers looks the member up on the class, then on
     *  the FIRST supertype of its H line (the superclass, unless that is Object), and so on, stopping at the first line
     *  it finds -- so an inherited member costs no line, and a key whose list DIFFERS from the inherited one (an
     *  override, an empty list included) always gets its own. (2) Each distinct list is written once, as an L line,
     *  and a T line names its number; (3) each member string is written once, as a numbered M line. Uncompressed the
     *  lines were 28 MB on the surveyed jars. */
    static List<String> templateLines() {
        Map<String, Set<String>> walk = new HashMap<>();
        TreeMap<String, Set<String>> emit = new TreeMap<>();
        for (String k : TEMPLATE.keySet()) {
            int p = k.indexOf('('), dot = k.lastIndexOf('.', p);
            String c = k.substring(0, dot), sig = k.substring(dot + 1);
            Set<String> mine = TEMPLATE.get(k);
            if (!mine.equals(inheritedTemplate(c, sig, walk, emit))) emit.put(k, mine);
        }
        // (3) every member string is written once, as a numbered M line, and a list names members by number
        TreeMap<String, Integer> mids = new TreeMap<>();
        for (Set<String> l : emit.values())
            for (String e : l) {
                int gt = e.indexOf('>');
                if (gt < 0) mids.putIfAbsent(e.substring(e.indexOf(':') + 1), 0);
                else { if (gt > 0) mids.putIfAbsent(e.substring(0, gt), 0); mids.putIfAbsent(e.substring(gt + 1), 0); }
            }
        int mn = 0;
        for (Map.Entry<String, Integer> e : mids.entrySet()) e.setValue(mn++);
        Map<Set<String>, String> enc = new HashMap<>();
        TreeMap<String, Integer> ids = new TreeMap<>();
        for (Set<String> l : emit.values()) {
            String x = enc.get(l);
            if (x == null) {
                List<String> es = new ArrayList<>();
                for (String e : l) {
                    int gt = e.indexOf('>');
                    if (gt < 0) { int c = e.indexOf(':'); es.add(e.substring(0, c + 1) + mids.get(e.substring(c + 1))); }
                    else es.add((gt > 0 ? String.valueOf(mids.get(e.substring(0, gt))) : "") + ">" + mids.get(e.substring(gt + 1)));
                }
                x = String.join(",", es);
                enc.put(l, x);
            }
            ids.putIfAbsent(x, 0);
        }
        int n = 0;
        for (Map.Entry<String, Integer> e : ids.entrySet()) e.setValue(n++);
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Integer> e : mids.entrySet()) out.add("M\t" + e.getValue() + "\t" + e.getKey());
        for (Map.Entry<String, Integer> e : ids.entrySet()) out.add("L\t" + e.getValue() + "\t" + e.getKey());
        for (Map.Entry<String, Set<String>> e : emit.entrySet()) out.add("T\t" + e.getKey() + "\t" + ids.get(enc.get(e.getValue())));
        return out;
    }

    /** What the consumer's walk reads for {@code sig} starting one H step above {@code c}, given the lines decided so far
     *  (decided supertypes-first by the recursion, so the answer never depends on key order). */
    static Set<String> inheritedTemplate(String c, String sig, Map<String, Set<String>> walk, TreeMap<String, Set<String>> emit) {
        LinkedHashSet<String> h = hierarchy().get(c);
        if (h == null || h.isEmpty()) return Set.of();
        return readTemplate(h.iterator().next(), sig, walk, emit, new HashSet<>());
    }

    static Set<String> readTemplate(String c, String sig, Map<String, Set<String>> walk, TreeMap<String, Set<String>> emit, Set<String> seen) {
        String k = c + "." + sig;
        Set<String> memo = walk.get(k);
        if (memo != null) return memo;
        if (!seen.add(c)) return Set.of();
        Set<String> r;
        Set<String> mine = TEMPLATE.get(k);
        Set<String> up = Set.of();
        LinkedHashSet<String> h = hierarchy().get(c);
        if (h != null && !h.isEmpty()) up = readTemplate(h.iterator().next(), sig, walk, emit, seen);
        if (mine != null && !mine.equals(up)) { emit.put(k, mine); r = mine; }
        else r = up;
        walk.put(k, r);
        return r;
    }

    static Set<String> selfDispatch(int j, String cls, List<Integer> roots) {
        TreeSet<String> out = new TreeSet<>();
        // (body, via): `via` is the overridable member whose body this is ("" for the called member's own), so the
        // consumer can stop at a member its class overrides -- that override, not this body, then runs
        ArrayDeque<Object[]> q = new ArrayDeque<>();
        for (int r : roots) q.add(new Object[] { r, "" });
        Set<String> seen = new HashSet<>();
        Set<Integer> root = new HashSet<>(roots);
        while (!q.isEmpty()) {
            Object[] it = q.poll();
            int n = (Integer) it[0];
            String via = (String) it[1];
            if (!seen.add(n + "|" + via)) continue;
            for (Object[] rc : receiverCalls(n)) {
                MethodInsnNode m = (MethodInsnNode) rc[0];
                int slot = (Integer) rc[1];
                if (slot != 0) {
                    // SOUNDNESS R1511 -- a dispatch on one of the ROOT body's own parameters (through a cast and a local):
                    // `DateTimeComparator.equals(Object o)` runs `((DateTimeComparator) o).getLowerLimit()`, which is the
                    // ARGUMENT's override. Recorded with the parameter's index and the dispatched owner, so the consumer
                    // can join the overrides of the argument's possible classes. Only the root's parameters: a this-call
                    // body's parameters are not the consumer's arguments.
                    if (!root.contains(n) || !via.isEmpty() || m.getOpcode() == Opcodes.INVOKESPECIAL || m.owner.startsWith("[")) continue;
                    int pi = paramIndex(nodeMethod.get(n), slot);
                    String own = m.owner;
                    int sl = own.lastIndexOf('/');
                    if (pi < 0 || sl <= 0 || jdkOwner(own) || runtimeOwner(own)) continue;
                    if (overridable(nodeJar.get(n), own, m.name, m.desc)) out.add("p" + pi + ":" + own + "." + m.name + m.desc);
                    continue;
                }
                if (m.getOpcode() == Opcodes.INVOKESPECIAL) {
                    for (int t : resolve(nodeJar.get(n), m.owner, m.name, m.desc)) q.add(new Object[] { t, via });
                    continue;
                }
                String next = via;
                if (overridable(j, cls, m.name, m.desc)) { out.add(via + ">" + m.name + m.desc); next = m.name + m.desc; }
                for (int t : resolve(j, cls, m.name, m.desc)) q.add(new Object[] { t, next });
            }
        }
        return out;
    }

    /** The parameter index (0-based, receiver excluded) whose value starts in local {@code slot}, or -1. */
    static int paramIndex(MethodNode mn, int slot) {
        int at = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1, i = 0;
        for (Type t : Type.getArgumentTypes(mn.desc)) {
            if (at == slot) return t.getSort() == Type.OBJECT ? i : -1;
            at += t.getSize(); i++;
        }
        return -1;
    }

    /** Whether a consumer subclass of {@code cls} (in another package) can override {@code name+desc}: decided by the
     *  nearest surveyed declaration -- superclass chain first, then superinterfaces; true when none is surveyed. */
    static boolean overridable(int j, String cls, String name, String desc) {
        ArrayDeque<String> q = new ArrayDeque<>();
        Set<String> vis = new HashSet<>();
        for (String c = cls; c != null; ) {
            int cj = jarOf(j, c);
            ClassNode cn = cls(cj, c);
            if (cn == null) break;
            for (MethodNode mn : cn.methods)
                if (mn.name.equals(name) && mn.desc.equals(desc)) return overridable(mn);
            q.addAll(cn.interfaces);
            c = cn.superName;
        }
        while (!q.isEmpty()) {
            String i = q.poll();
            if (!vis.add(i)) continue;
            ClassNode in = cls(jarOf(j, i), i);
            if (in == null) continue;
            for (MethodNode mn : in.methods)
                if (mn.name.equals(name) && mn.desc.equals(desc)) return overridable(mn);
            q.addAll(in.interfaces);
        }
        return true;
    }

    static boolean overridable(MethodNode mn) {
        return (mn.access & (Opcodes.ACC_FINAL | Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) == 0
                && (mn.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0;
    }

    /** The calls in body {@code n} whose receiver is provably the value a local SLOT held on entry -- slot 0 of an
     *  instance body is {@code this}, the others its parameters -- through casts and stores to locals: each
     *  {@code [MethodInsnNode, slot]}. Empty for a body the analyzer cannot read. */
    static List<Object[]> receiverCalls(int n) {
        List<Object[]> memo = THIS_CALLS.get(n);
        if (memo != null) return memo;
        List<Object[]> out = new ArrayList<>();
        MethodNode mn = nodeMethod.get(n);
        if ((mn.access & Opcodes.ACC_STATIC) == 0 && mn.instructions != null && mn.instructions.size() > 0) {
            try {
                org.objectweb.asm.tree.analysis.Frame<org.objectweb.asm.tree.analysis.SourceValue>[] fr =
                        new org.objectweb.asm.tree.analysis.Analyzer<>(new org.objectweb.asm.tree.analysis.SourceInterpreter())
                                .analyze(nodeOwner.get(n), mn);
                for (int i = 0; i < mn.instructions.size(); i++) {
                    if (!(mn.instructions.get(i) instanceof MethodInsnNode m) || fr[i] == null) continue;
                    int op = m.getOpcode();
                    if (op != Opcodes.INVOKEVIRTUAL && op != Opcodes.INVOKEINTERFACE && op != Opcodes.INVOKESPECIAL) continue;
                    if (m.owner.startsWith("[") || m.name.equals("<clinit>")) continue;
                    int ri = fr[i].getStackSize() - Type.getArgumentTypes(m.desc).length - 1;
                    if (ri < 0) continue;
                    int slot = entrySlot(mn, fr, fr[i].getStack(ri), 0);
                    if (slot >= 0) out.add(new Object[] { m, slot });
                }
            } catch (Exception | LinkageError e) { out.clear(); }
        }
        THIS_CALLS.put(n, out);
        return out;
    }

    /** The local slot whose ENTRY value {@code v} provably is (every source agrees), or -1. Follows ALOAD of a local
     *  never stored on that path (its entry value), ASTORE into a local, and CHECKCAST. */
    static int entrySlot(MethodNode mn, org.objectweb.asm.tree.analysis.Frame<org.objectweb.asm.tree.analysis.SourceValue>[] fr,
            org.objectweb.asm.tree.analysis.SourceValue v, int depth) {
        if (depth > 8 || v.insns.isEmpty()) return -1;
        int slot = -2;
        for (AbstractInsnNode s : v.insns) {
            int idx = mn.instructions.indexOf(s), r;
            if (fr[idx] == null) return -1;
            if (s instanceof org.objectweb.asm.tree.VarInsnNode x && x.getOpcode() == Opcodes.ALOAD) {
                org.objectweb.asm.tree.analysis.SourceValue l = fr[idx].getLocal(x.var);
                r = l.insns.isEmpty() ? x.var : entrySlot(mn, fr, l, depth + 1);
            } else if (s instanceof org.objectweb.asm.tree.VarInsnNode x && x.getOpcode() == Opcodes.ASTORE) {
                r = entrySlot(mn, fr, fr[idx].getStack(fr[idx].getStackSize() - 1), depth + 1);
            } else if (s.getOpcode() == Opcodes.CHECKCAST) {
                r = entrySlot(mn, fr, fr[idx].getStack(fr[idx].getStackSize() - 1), depth + 1);
            } else return -1;
            if (r < 0 || (slot != -2 && slot != r)) return -1;
            slot = r;
        }
        return slot;
    }

    static Integer node(int j, String owner, String nameDesc) { return nodeId.get(j + "|" + owner + "." + nameDesc); }

    public static void main(String[] a) throws Exception {
        if (a.length > 0 && a[0].equals("--pure-only")) { pureOnly(a); return; }
        if (a.length > 0 && a[0].equals("--jdk-packages")) { jdkPackagesOut(a); return; }
        Path out = Path.of(a[0]), witness = Path.of(a[1]);
        hedgeOut = System.getProperty("framework.hedgeOut");
        // the floor: the previous tables' members (reach rows; A/U hedge lines)
        String floorIn = System.getProperty("framework.floorIn");
        if (floorIn != null)
            for (String fp : floorIn.split(",")) {
                if (fp.isEmpty() || !Files.exists(Path.of(fp))) continue;
                for (String l : Files.readAllLines(Path.of(fp), StandardCharsets.UTF_8)) {
                    if (l.isEmpty() || l.startsWith("#")) continue;
                    String[] c = l.split("\t");
                    if (c.length >= 2 && (c[0].equals("A") || c[0].equals("U"))) FLOOR.add(c[1]);
                    else if (c.length >= 2 && c[0].length() > 1) FLOOR.add(c[0]);   // a reach row: key <TAB> effects
                }
            }
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
                    for (JsonElement x : inf)
                        if (x.getAsString().equals("Unknown")) {
                            Integer aid = nodeId.get(j + "|" + f.get("hash").getAsString());
                            if (aid != null) UNK_ANY.add(aid);
                        }
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
        //
        // SOUNDNESS R1468 — BUT THE STAND-IN IS A CONCRETE EFFECT ONLY WHERE THE HIDDEN DISPATCH CAN PERFORM IT. Put back
        // unconditionally, the rule's charge landed on bodies whose unfollowable dispatch has nothing to do with it:
        // EXECUTED, `new RestTemplate()` opens no connection (spring-web 5.3.39 and 6.1.10, SecurityManager connect
        // trace) and the table charged it Net, because its converter set-up reaches a dispatch the table cannot follow
        // and RestTemplate's pure validateConverters() is under the whole-owner Net rule. 93 (member, effect) pairs had
        // only this stand-in as their charge. So per body the generator now also records WHAT the unfollowable
        // dispatches in its closure can do: the concrete effects of the surveyed implementers of each abstract target
        // (`oImpl`), closed over the same edges. The rule's charge is kept where an implementer carries the same effect
        // (RabbitMessagingTemplate.receiveAndConvert: the abstract doReceive is implemented by a body that reaches the
        // broker — EXECUTED, it connects); where none does — an unsurveyed owner, implementers that are Unknown or
        // charged with other effects — the stand-in is NOT a charge, and the member is DISCLOSED instead (a `C` line,
        // Unknown[dispatch:<an unfollowable member of its closure>]). Never nothing: `LOST` also keeps every downstream
        // reader (implementersUnvouched, returnTypeInert, BROAD, crossJar) seeing the body as unvouched, exactly as it did
        // while the stand-in was a charge.
        int[] dropC = new int[N];
        boolean[] opaqueC = new boolean[N];
        int[] oImpl = new int[N];
        String[] oRep = new String[N];
        for (int n = 0; n < N; n++) {
            MethodNode mn = nodeMethod.get(n);
            if (mn.instructions == null) continue;
            for (AbstractInsnNode in : mn.instructions) {
                if (!(in instanceof MethodInsnNode m) || m.owner.startsWith("[")) continue;
                if (pureKeys.contains(m.owner + "." + m.name + m.desc)) dropC[n] |= ruleMask(m.owner, m.name, m.desc);
                else if (!jdkOwner(m.owner) && !loggingFrontier(m.owner) && !runtimeOwner(m.owner)
                        && !ruleCharges(m.owner, m.name, m.desc) && resolve(nodeJar.get(n), m.owner, m.name, m.desc).isEmpty()
                        && !inheritedFinalJdk(nodeJar.get(n), m.owner, m.name, m.desc)          // SOUNDNESS R1479
                        && (!classJars.containsKey(m.owner) || implementersUnvouched(m.owner, m.name, m.desc, eff))) {
                    opaqueC[n] = true;
                    if (classJars.containsKey(m.owner)) oImpl[n] |= implementersMask(m.owner, m.name, m.desc, eff);
                    // the member the disclosure names: an abstract member the surveyed jars declare first, then an
                    // unsurveyed owner's, then a JDK method a surveyed class only inherits — the least informative (a
                    // FINAL one, Enum.ordinal, is not a dispatch at all: R1479); deterministic within a rank. The rank is
                    // a sort prefix, stripped on output.
                    int rank = !classJars.containsKey(m.owner) ? 1 : declaredInUniverse(nodeJar.get(n), m.owner, m.name + m.desc) ? 0 : 2;
                    String k = rank + "|" + m.owner.replace('/', '.') + "." + m.name;
                    if (oRep[n] == null || k.compareTo(oRep[n]) < 0) oRep[n] = k;
                }
            }
        }
        {   // close all four over the same statically-resolved edges, callers inherit from callees
            ArrayDeque<Integer> q = new ArrayDeque<>();
            boolean[] inq = new boolean[N];
            for (int n = 0; n < N; n++) if (dropC[n] != 0 || opaqueC[n]) { q.add(n); inq[n] = true; }
            while (!q.isEmpty()) {
                int n = q.poll(); inq[n] = false;
                for (int p : pred[n]) {
                    int nd = dropC[p] | dropC[n];
                    boolean no = opaqueC[p] || opaqueC[n];
                    int ni = oImpl[p] | oImpl[n];
                    String nr = oRep[n] != null && (oRep[p] == null || oRep[n].compareTo(oRep[p]) < 0) ? oRep[n] : oRep[p];
                    if (nd != dropC[p] || no != opaqueC[p] || ni != oImpl[p] || !Objects.equals(nr, oRep[p])) {
                        dropC[p] = nd; opaqueC[p] = no; oImpl[p] = ni; oRep[p] = nr;
                        if (!inq[p]) { q.add(p); inq[p] = true; }
                    }
                }
            }
        }
        int reapplied = 0, disclosed = 0;
        LOST = new int[N];
        OPAQUE_REP = oRep;
        for (int n = 0; n < N; n++) {
            if (!opaqueC[n]) continue;
            int stand = dropC[n] & ~eff[n];
            if (stand == 0) continue;
            int keep = stand & oImpl[n];
            // `Llm` is a LABEL no body performs (the model-SDK blanket's name for the request it sends), so no implementer
            // can carry it: where the body is charged `Net` — its own, or a stand-in kept above — a stand-in `Llm` is the
            // label of that request and is kept too. MEASURED without this (the independent checker flagged all six):
            // OpenAiApi.chatCompletionEntity(req, headers)/embeddings and four sibling request methods lost `Llm` while
            // their own body stayed `Net` — real model calls.
            if (((eff[n] | keep) & bit(Effect.NET.specName())) != 0) keep |= stand & bit(Effect.LLM.specName());
            if (keep != 0) { eff[n] |= keep; reapplied++; }
            if ((stand & ~keep) != 0) { LOST[n] = stand & ~keep; disclosed++; }
        }
        System.err.println("framework-reach: " + reapplied + " bodies keep a P member's rule charge (opaque closure, an "
                + "implementer of the unfollowable dispatch carries it); " + disclosed + " disclose it instead (R1468)");
        hiddenReach(N, succ, eff);
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
            int dot = k.lastIndexOf('.', k.indexOf('('));
            int rule = ruleMask(k.substring(0, dot), k.substring(dot + 1, k.indexOf('(')), desc);
            if (returnTypeInert(Type.getReturnType(desc), PURE_JAR.get(k), rule)) pureNext.add(k);
        }
        String pout = System.getProperty("framework.pureOut");
        if (pout != null) {
            StringBuilder pb = new StringBuilder();
            for (String k : pureNext) pb.append(k).append('\n');
            Files.writeString(Path.of(pout), pb.toString(), StandardCharsets.UTF_8);
        }
        PURE.clear(); PURE.addAll(pureIn);          // the hedge's P lines are the list the scans used
        // 6. entries: every consumer-callable member of every public class under a covered prefix
        List<String> wit0 = new ArrayList<>();   // SOUNDNESS R1097 witness lines, appended to the witness below
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
                        else if (tg.stream().allMatch(FrameworkReachGen::unkAny) && (FLOOR.contains(cn.name + "." + sig)
                                || tg.stream().allMatch(t -> eff[t] == 0))) FLOORED.add(cn.name + "." + sig);
                    }
                    if (tg.isEmpty()) continue;
                    MethodNode decl = nodeMethod.get(tg.get(0));
                    boolean callable = (decl.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0;
                    if (!callable || name.equals("<clinit>")) continue;
                    // SOUNDNESS R1511 — the overridable members this body runs on its own receiver (T lines)
                    if (framework && (cn.access & (Opcodes.ACC_FINAL | Opcodes.ACC_INTERFACE)) == 0 && (decl.access & Opcodes.ACC_STATIC) == 0)
                        TEMPLATE.computeIfAbsent(cn.name + "." + sig, k -> new TreeSet<>()).addAll(selfDispatch(j, cn.name, tg));
                    LinkedHashSet<Integer> rs = new LinkedHashSet<>(tg);
                    if ((decl.access & Opcodes.ACC_STATIC) != 0 || name.equals("<init>")) rs.addAll(clinits(j, cn.name));
                    int declared = 0, declaredLost = 0;
                    for (int r : rs) { declared |= eff[r]; declaredLost |= LOST[r]; }
                    String key = cn.name + "." + sig;
                    if ((decl.access & Opcodes.ACC_STATIC) == 0 && !name.equals("<init>") && DISPATCH_ROOTS) {
                        // SOUNDNESS R1096 — the engine's bounded CHA (Candor#virtualDispatch): a NARROW fan-out is
                        // charged; a BROAD one (more than Rules.CHA_FANOUT_LIMIT bodies) is not smeared into the row but
                        // DISCLOSED — an `A` (dispatch) line — and only where an override can do what the declared body
                        // cannot, since a fan-out that adds nothing changes nothing.
                        List<Integer> ov = overriders(j, cn.name, name, desc, tg);
                        if (ov.size() + tg.size() <= Rules.CHA_FANOUT_LIMIT) rs.addAll(ov);
                        else {
                            int extra = 0;
                            for (int r : ov) extra |= eff[r] | LOST[r];     // R1468: a disclosed stand-in counts as it did charged
                            if ((extra & ~(declared | declaredLost)) != 0) BROAD.add(key);
                        }
                    }
                    int mask = 0, lost = 0;
                    String rep = null;
                    for (int r : rs) {
                        mask |= eff[r];
                        if (LOST[r] != 0) {
                            lost |= LOST[r];
                            if (OPAQUE_REP[r] != null && (rep == null || OPAQUE_REP[r].compareTo(rep) < 0)) rep = OPAQUE_REP[r];
                        }
                    }
                    if (declared == 0 && mask != 0) OVERRIDE_ONLY.add(key);   // charged by an override and nothing else
                    // SOUNDNESS R1468 — a stand-in this member's row no longer carries is disclosed (a `C` line), never dropped
                    if (framework && (lost & ~mask) != 0 && rep != null) {
                        CLOSURE.merge(key, rep, (x, y) -> x.compareTo(y) <= 0 ? x : y);
                        CLOSURE_LOST.merge(key, lost & ~mask, (x, y) -> x | y);
                    }
                    if (framework && DISPATCH_ROOTS && !BROAD.contains(key))
                        crossJar(j, cn, name, desc, decl, mask | lost | ruleMask(cn.name, name, desc), eff, wit0);
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
                    if (ptr[cur] == null || ptr[cur][i] < 0) { path.add("(R1052 5a: a P member's rule charge kept — opaque closure, an implementer of the unfollowable dispatch carries it, R1468)"); break; }
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
            // SOUNDNESS R1096 — a `U` member stays disclosed even when its row is now CHARGED: since the dispatch union,
            // a charge can come from an OVERRIDE alone (OVERRIDE_ONLY) while the declared body is still one the scan read
            // only as Unknown. Dropping the U there (the old `charged` exclusion) removed 53 disclosures for a charge on a
            // different body. The engine applies a U line beside a table charge (FrameworkReach#hedgeKind).
            for (Map.Entry<String, String> h : HEDGE.entrySet())
                if (!charged.contains(h.getKey()) || (h.getValue().equals("U") && OVERRIDE_ONLY.contains(h.getKey())))
                    hl.add(h.getValue() + "\t" + h.getKey());
            for (String k : BROAD) if (!HEDGE.containsKey(k)) hl.add("A\t" + k);   // SOUNDNESS R1096 broad dispatch (one line per key)
            for (String k : FLOORED)                                                     // SOUNDNESS R1189 the floor
                if (!HEDGE.containsKey(k) && !BROAD.contains(k) && !charged.contains(k)) { hl.add("U\t" + k); floored++; }
            System.err.println("framework-reach: " + floored + " members kept at U by the floor (R1189) or hedged by R1193");
            // SOUNDNESS R1468 — a member whose row lost a step-5a stand-in, and that no A/U line above discloses already:
            // Unknown[dispatch:<the unfollowable member>] (FrameworkReach#closureTarget), beside a charge or alone.
            Set<String> disclosedAU = new HashSet<>();
            for (String l : hl) if (l.startsWith("A\t") || l.startsWith("U\t")) disclosedAU.add(l.substring(2));
            int closures = 0;
            for (Map.Entry<String, String> c : CLOSURE.entrySet())
                if (!disclosedAU.contains(c.getKey())) { hl.add("C\t" + c.getKey() + "\t" + c.getValue().substring(2)); closures++; }
            System.err.println("framework-reach: " + closures + " members disclose an unfollowable closure instead of a rule stand-in (R1468)");
            for (Map.Entry<String, TreeSet<String>> x : XJAR.entrySet())                  // SOUNDNESS R1097
                hl.add("O\t" + x.getKey() + "\t" + String.join(",", x.getValue()));
            for (String pk : PURE) hl.add("P\t" + pk);
            hl.addAll(hierarchyLines());                                                 // SOUNDNESS R1509
            hl.addAll(templateLines());                                                  // SOUNDNESS R1511
            Collections.sort(hl);
            MessageDigest hm = MessageDigest.getInstance("SHA-256");
            for (String r : hl) hm.update((r + "\n").getBytes(StandardCharsets.UTF_8));
            StringBuilder hb = new StringBuilder();
            for (String h : header) hb.append(h).append('\n');
            hb.append("# hedge: J = a JDK package (runtime), S = a surveyed framework class, A/U = a framework member the\n");
            hb.append("# table cannot vouch for (A: no body — dispatch; U: the scan read it only as Unknown, or the\n");
            hb.append("# previous table had a line for it and its body still carries Unknown — the R1189 floor — or its bodies carry\n");
            hb.append("# Unknown and the closure reaches no concrete effect, R1193). See FrameworkReach.\n");
            hb.append("# P = a member a NAME rule charges whose surveyed body is a proven-pure field accessor (R1052).\n");
            hb.append("# O = a public member overridden in ANOTHER surveyed jar by a body that can do more than the row says;\n");
            hb.append("#     the overriding classes follow (R1097). See FrameworkReach#crossJarOverriders.\n");
            hb.append("# H = a surveyed class's DIRECT supertypes (superclass first, then interfaces; Object omitted), so a consumer\n");
            hb.append("#     scan can tell that its own class reaches a framework type THROUGH a framework class (R1509).\n");
            hb.append("# T = a member of a subclassable surveyed class whose body (and the bodies it runs on the same receiver) calls\n");
            hb.append("#     back an overridable member on `this`; the number of the L line listing those members follows (R1511):\n");
            hb.append("#     `via>member` (reached through the body of `via`, an overridable member; empty for the called member's own),\n");
            hb.append("#     or `p<i>:owner.member` (dispatched on the called body's i-th parameter).\n");
            hb.append("#     Written only where it differs from what the walk up the H lines' first entries reads. See Cha#templateCallbacks.\n");
            hb.append("# L = a numbered list of T entries, members named by M number; M = a numbered member (R1511).\n");
            hb.append("# C = a member whose closure reaches a dispatch the table cannot follow, where a NAME rule's charge used to\n");
            hb.append("#     stand in for it and no surveyed implementer carries that effect; the unfollowed member follows (R1468).\n");
            hb.append("# entries ").append(hl.size()).append('\n');
            hb.append("# content-sha256 ").append(HexFormat.of().formatHex(hm.digest())).append('\n');
            for (String r : hl) hb.append(r).append('\n');
            Files.writeString(Path.of(hedgeOut), hb.toString(), StandardCharsets.UTF_8);
        }
        wit.addAll(wit0);
        for (Map.Entry<String, String> c : CLOSURE.entrySet())    // SOUNDNESS R1468: the stand-ins disclosed, not charged
            wit.add(c.getKey() + "\t" + names(CLOSURE_LOST.get(c.getKey())) + "\tR1468-DISCLOSED\tdispatch:" + c.getValue().substring(2));
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
                + rows.size() + " charged rows; " + DISPATCH_ADDED + " override targets added by dispatch (R1096); "
                + XJAR.size() + " members overridden across jars beyond their row (R1097)");
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

    /** Whether a value of type {@code t}, handed back by a proven-pure member a NAME rule charges with {@code rule}, cannot
     *  carry that effect to a later call that only the rule's charge stood in for: a primitive, a JDK VALUE or collection
     *  type (java.lang / java.util — not java.util.concurrent or java.util.stream, whose futures and streams run deferred
     *  work — java.time, java.math, java.net.URI), or a SURVEYED framework type none of whose ABSTRACT members a consumer
     *  can call is one the hedge discloses as `dispatch:` ({@link #implementersUnvouched}, the A-line rule) AND whose hidden
     *  dispatch can perform the rule's effect ({@link #canPerform}). Measured reason for the guard: MongoTemplate.query(X.class)
     *  is pure, and the Db is `.all()` on the ExecutableFind INTERFACE it returns, hedged `dispatch:` — so dropping the
     *  blanket on query() turned `deny Db` 1 -> 0 behind an Unknown. A CONCRETE member is answered at the consumer by the
     *  table from its own body, and an abstract member a NAME rule charges at the consumer's own call (Spring AI's
     *  {@code ChatOptions.copy()} under the model-SDK blanket) keeps that charge — neither can lose its label this way.
     *
     *  <p>SOUNDNESS R1476 — until then ANY hedged abstract member blocked, whatever it could do; since R1471 widened the
     *  A-line rule to every implementer carrying Unknown, that dropped the P line of {@code RestTemplate.getUriTemplateHandler()}
     *  ({@code getfield; areturn}) because {@code UriTemplateHandler.expand} is hedged, and a consumer reading the handler was
     *  charged {@code Net} again — EXECUTED, an expand opens nothing. The disclosure is the A line's job and it stays: the
     *  consumer's later {@code expand} still reads {@code Unknown[dispatch:...]}. The rule's charge on the getter is kept
     *  only where that hidden call can be the rule's effect.
     *
     *  <p>One level deep; anything unsurveyed is not inert. Needs the closed effect masks, which is why derive.sh iterates
     *  the P list to a fixed point (fewer P lines -> more charges -> fewer inert types, so it only shrinks). */
    static boolean returnTypeInert(Type t, int j, int rule) {
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
        String ck = n + "|" + rule;
        Boolean m = INERT.get(ck);
        if (m != null) return m;
        INERT.put(ck, false);                       // a cycle is not a proof
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
                // concrete charge the chain carried (the consumer otherwise gets a `dispatch:` Unknown), so it must not
                // be able to perform the blanket's effect through any surveyed implementer (R1476).
                if (tg.isEmpty() && implementersUnvouched(n, name, desc, EFF) && !ruleCharges(n, name, desc)
                        && canPerform(n, name, desc, rule)) r = false;
                if (!r) break;
            }
        }
        INERT.put(ck, r);
        return r;
    }

    // ── SOUNDNESS R1476 — WHAT A HIDDEN DISPATCH CAN PERFORM ────────────────────────────────────────────────────────
    /** Per body: the concrete effects (and stand-ins disclosed instead of charged, {@link #LOST}) its statically-resolved
     *  closure reaches, with {@link #OUTSIDE} set where that closure calls code outside the surveyed jars and the JDK — an
     *  unsurveyed owner, an abstract member no surveyed class implements, a member inherited from an unsurveyed ancestor —
     *  plus the concrete effects (not {@code OUTSIDE}) of the surveyed implementers of every abstract member it calls: the
     *  same one level R1468's step 5a reads. Computed once per generator run, after step 5a. */
    static int[] HIDDEN;
    /** Above every effect bit: the closure reaches code the table cannot see (outside the surveyed jars and the JDK). */
    static final int OUTSIDE = 1 << 30;

    /** Whether a call to the abstract {@code owner.name+desc} can perform an effect in {@code rule}: it has no surveyed
     *  implementer (the implementation ships elsewhere: a driver, a container), or one of them reaches the effect, or
     *  reaches code outside the surveyed jars and the JDK. `Llm` is a label no body performs, so a body that reaches
     *  `Net` can perform a model-SDK rule's `Llm`. Measured counter-case kept by this: KafkaTemplate.getProducerFactory()
     *  — the factory's surveyed implementers read Clock/Log, and createProducer() opens the producer's connections inside
     *  kafka-clients, which is not surveyed (EXECUTED: 9 connections). */
    static boolean canPerform(String owner, String name, String desc, int rule) {
        List<Integer> ib = implementerBodies(owner, name, desc);
        if (ib.isEmpty()) return true;
        int want = rule | OUTSIDE;
        if ((rule & bit(Effect.LLM.specName())) != 0) want |= bit(Effect.NET.specName());
        for (int t : ib) if ((HIDDEN[t] & want) != 0) return true;
        return false;
    }

    /** The surveyed bodies a call to the abstract {@code owner.name+desc} can run: the walk of {@link #implementersMask}. */
    static List<Integer> implementerBodies(String owner, String name, String desc) {
        String key = owner + "." + name + desc;
        List<Integer> hit = IMPL_BODIES.get(key);
        if (hit != null) return hit;
        implementersUnvouched(owner, name, desc, EFF == null ? new int[nodeKey.size()] : EFF);    // builds `subs`
        ArrayDeque<String> q = new ArrayDeque<>(subs.getOrDefault(owner, List.of()));
        Set<String> seen = new HashSet<>();
        List<Integer> out = new ArrayList<>();
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            q.addAll(subs.getOrDefault(c, List.of()));
            List<Integer> js = classJars.get(c);
            if (js == null) continue;
            for (int j : js) {
                ClassNode cn = cls(j, c);
                if (cn == null || (cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0) continue;
                for (int t : resolve(j, c, name, desc)) if (!out.contains(t)) out.add(t);
            }
        }
        IMPL_BODIES.put(key, out);
        return out;
    }
    static final Map<String, List<Integer>> IMPL_BODIES = new HashMap<>();

    static void hiddenReach(int N, int[][] succ, int[] eff) {
        int[] own = new int[N];
        List<List<Integer>> disp = new ArrayList<>(N);
        for (int n = 0; n < N; n++) {
            own[n] = eff[n] | LOST[n];
            List<Integer> d = new ArrayList<>();
            disp.add(d);
            MethodNode mn = nodeMethod.get(n);
            if (mn.instructions == null) continue;
            int j = nodeJar.get(n);
            for (AbstractInsnNode in : mn.instructions) {
                String o, nm, ds;
                if (in instanceof MethodInsnNode m) { o = m.owner; nm = m.name; ds = m.desc; }
                else if (in instanceof InvokeDynamicInsnNode x && x.bsm != null
                        && x.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory") && x.bsmArgs.length > 1
                        && x.bsmArgs[1] instanceof Handle h) { o = h.getOwner(); nm = h.getName(); ds = h.getDesc(); }
                else continue;
                if (o.startsWith("[") || jdkOwner(o) || loggingFrontier(o) || runtimeOwner(o) || ruleCharges(o, nm, ds)) continue;
                if (!resolve(j, o, nm, ds).isEmpty()) continue;                  // a statically-resolved edge: in succ
                if (!classJars.containsKey(o) || inheritedFromOutside(j, o)) { own[n] |= OUTSIDE; continue; }
                if (inheritedFinalJdk(j, o, nm, ds)) continue;                   // SOUNDNESS R1479
                List<Integer> ib = implementerBodies(o, nm, ds);
                if (ib.isEmpty()) { own[n] |= OUTSIDE; continue; }
                d.addAll(ib);
            }
        }
        List<List<Integer>> rev = new ArrayList<>(N);
        for (int n = 0; n < N; n++) rev.add(new ArrayList<>());
        for (int n = 0; n < N; n++) for (int x : succ[n]) rev.get(x).add(n);
        closeOver(rev, own);
        int[] h = new int[N];
        for (int n = 0; n < N; n++) { h[n] = own[n]; for (int t : disp.get(n)) h[n] |= own[t] & ~OUTSIDE; }
        closeOver(rev, h);
        HIDDEN = h;
    }

    /** Callers inherit their callees' bits: least fixpoint over the reverse statically-resolved edges. */
    static void closeOver(List<List<Integer>> rev, int[] a) {
        int N = a.length;
        ArrayDeque<Integer> wl = new ArrayDeque<>();
        boolean[] in = new boolean[N];
        for (int n = 0; n < N; n++) if (a[n] != 0) { wl.add(n); in[n] = true; }
        while (!wl.isEmpty()) {
            int n = wl.poll(); in[n] = false;
            for (int p : rev.get(n)) {
                int add = a[n] & ~a[p];
                if (add == 0) continue;
                a[p] |= add;
                if (!in[p]) { wl.add(p); in[p] = true; }
            }
        }
    }

    /** Whether {@code owner}'s superclass chain or superinterfaces leave the surveyed jars for a class that is neither
     *  JDK nor a language runtime: a member that resolves to no surveyed body may then be that ancestor's. */
    static boolean inheritedFromOutside(int from, String owner) {
        ArrayDeque<String> q = new ArrayDeque<>(); q.add(owner);
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            if (jdkOwner(c) || runtimeOwner(c)) continue;
            ClassNode cn = cls(jarOf(from, c), c);
            if (cn == null) return true;
            if (cn.superName != null) q.add(cn.superName);
            q.addAll(cn.interfaces);
        }
        return false;
    }

    /** SOUNDNESS R1479 — a FINAL {@code java.lang.Enum} / {@code java.lang.Object} member called through a surveyed class
     *  that only inherits it ({@code EncodingMode.equals}, {@code ordinal}): resolution leaves the surveyed jars for the
     *  JDK body every JDK release declares final, so the call is a JDK call, not a dispatch the table cannot follow. Only
     *  where every class between the owner and {@code java/lang/Enum} (or {@code Object}) is surveyed and none declares
     *  the member. Measured reach in step 5a: 2,463 of 110,469 opaque bodies stop being opaque, none of which reaches a
     *  P member, so neither table moves; in {@link #hiddenReach} it is what lets an enum comparison inside a URI builder
     *  read as the JDK call it is. */
    static boolean inheritedFinalJdk(int from, String owner, String name, String desc) {
        String nd = name + desc;
        boolean enumFinal = nd.equals("ordinal()I") || nd.equals("name()Ljava/lang/String;") || nd.equals("equals(Ljava/lang/Object;)Z")
                || nd.equals("hashCode()I") || nd.equals("compareTo(Ljava/lang/Enum;)I") || nd.equals("getDeclaringClass()Ljava/lang/Class;");
        boolean objectFinal = nd.equals("getClass()Ljava/lang/Class;");
        if (!enumFinal && !objectFinal) return false;
        String c = owner;
        int j = jarOf(from, c);
        Set<String> seen = new HashSet<>();
        while (c != null && seen.add(c)) {
            if (c.equals("java/lang/Enum")) return true;
            if (c.equals("java/lang/Object")) return objectFinal;
            ClassNode cn = cls(j, c);
            if (cn == null) return false;
            for (MethodNode mn : cn.methods) if (mn.name.equals(name) && mn.desc.equals(desc)) return false;
            c = cn.superName;
            j = c == null ? -1 : jarOf(j, c);
        }
        return false;
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

    /** SOUNDNESS R1096 — A CALL THE TABLE RESOLVES TO A FRAMEWORK MEMBER RUNS WHICHEVER SURVEYED OVERRIDE THE RECEIVER
     *  SELECTS. {@link #resolve} answers JVMS method RESOLUTION, which is the declared (or inherited) body for the
     *  STATIC owner; a consumer's {@code AbstractSqlPagingQueryProvider.init(ds)} then read the base's empty body while
     *  the {@code DerbyPagingQueryProvider} it was handed opened a connection (EXECUTED: {@code deny Db} exited 0 on the
     *  base spelling, 1 on the subclass's). This is the CHA the engine applies to project code (Cha#chaTargets),
     *  applied over the surveyed artefact's own hierarchy: every class in the SAME jar that is a subtype of the static
     *  owner and DECLARES a concrete {@code (name, desc)} — an inherited body is already some ancestor's, which is
     *  either {@code resolved} or another declarer here. The same exemptions as the engine's dispatch: the Object
     *  protocol (Candor#isObjectProtocolExempt) is not fanned out, and a CHA-exempt verb (Cha#isChaExemptMethod) only
     *  while the fan-out is narrow (≤ Rules.CHA_FANOUT_LIMIT). A static, private, final or constructor target, or one
     *  in a final class, has no overrides. Abstract members resolve to nothing and keep their A-line rule. */
    static List<Integer> overriders(int from, String owner, String name, String desc, List<Integer> resolved) {
        if (resolved.size() != 1 || name.startsWith("<") || loggingFrontier(owner)) return List.of();
        MethodNode decl = nodeMethod.get(resolved.get(0));
        if ((decl.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL)) != 0) return List.of();
        if (Candor.isObjectProtocolExempt(name, desc)) return List.of();
        int j = jarOf(from, owner);
        if (j < 0) return List.of();
        ClassNode oc = cls(j, owner);
        if (oc == null || (oc.access & Opcodes.ACC_FINAL) != 0) return List.of();
        String nd = name + desc;
        List<Integer> out = new ArrayList<>();
        for (String sub : subtypes(j, owner)) {
            ClassNode sc = cls(j, sub);
            if (sc == null || loggingFrontier(sub)) continue;
            for (MethodNode mn : sc.methods)
                if (mn.name.equals(name) && mn.desc.equals(desc)
                        && (mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) == 0) {
                    Integer id = node(j, sub, nd);
                    if (id != null && !resolved.contains(id) && !out.contains(id)) out.add(id);
                }
        }
        if (closureDispatch(owner, name)) return List.of();
        if (Cha.isChaExemptMethod(owner, name, desc) && out.size() > Rules.CHA_FANOUT_LIMIT) return List.of();
        DISPATCH_ADDED += out.size();
        return out;
    }

    /** SOUNDNESS R1097 — the members {@link #overriders} cannot see: R1096's union reads the SAME jar's hierarchy, so a
     *  public member whose override ships in ANOTHER surveyed jar was charged its declared body alone. MEASURED (spec
     *  lane, EXECUTED): ktor-http {@code OutgoingContent.getContentLength()} handed ktor-server-core's
     *  {@code LocalFileContent} returned the file's size, and the consumer's row was ABSENT ({@code deny Fs} and
     *  {@code deny Fs Unknown} exit 0). The table cannot union those bodies in: whether the other jar is on a consumer's
     *  class path is not something it knows, and charging every caller of {@code AbstractResource.isFile} with
     *  spring-web's {@code Fs} would fabricate for every program without spring-web. So it records the fact — an
     *  {@code O} line naming the overriding classes — and the ENGINE decides at the call: an overriding class its scan
     *  or a chained report can see is RESOLVED (charged through that body), one it cannot see is DISCLOSED as
     *  {@code Unknown[dispatch]} (FrameworkReach#crossJarOverriders, Candor#frameworkCrossJar).
     *
     *  <p>Only what a CONSUMER can reach: a public, non-final member of a public, non-final class, an instance member
     *  ({@code <init>} and statics have no overrides), and an override in a jar that does not itself ship the owner (a
     *  jar shipping the owner is a version of the same artefact, already intersected). A protected member is reached
     *  from a consumer only on a receiver of the consumer's own subtype, which no other jar's class can be. The
     *  override must add a concrete effect the row (its declared body, R1096's union and any NAME rule on the member)
     *  does not carry, or be a body the engine's scan could read only as {@code Unknown}. The same exemptions as R1096:
     *  the Object protocol and closure-object dispatch. */
    static void crossJar(int j, ClassNode cn, String name, String desc, MethodNode decl, int mask, int[] eff, List<String> wit0) {
        if ((cn.access & (Opcodes.ACC_FINAL | Opcodes.ACC_INTERFACE)) == Opcodes.ACC_FINAL) return;
        if ((decl.access & Opcodes.ACC_PUBLIC) == 0 || (decl.access & (Opcodes.ACC_FINAL | Opcodes.ACC_STATIC)) != 0) return;
        if (Candor.isObjectProtocolExempt(name, desc) || closureDispatch(cn.name, name)) return;
        List<int[]> subs = xsubs().get(cn.name);
        if (subs == null) return;
        String nd = name + desc, key = cn.name + "." + nd;
        for (int[] kc : subs) {
            String sub = XNAMES.get(kc[1]);
            ClassNode sc = cls(kc[0], sub);
            if (sc == null) continue;
            for (MethodNode mn : sc.methods) {
                if (!mn.name.equals(name) || !mn.desc.equals(desc)
                        || (mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) continue;
                Integer id = node(kc[0], sub, nd);
                if (id == null) continue;
                int add = eff[id] & ~mask;
                // R1471: an Unknown-ONLY test missed a widened body. R1468: a stand-in the override's row discloses rather
                // than charges is still something it can do beyond the row.
                boolean unk = (eff[id] == 0 && unkAny(id)) || (LOST[id] & ~mask) != 0;
                if (add == 0 && !unk) continue;
                XJAR.computeIfAbsent(key, k -> new TreeSet<>()).add(sub);
                wit0.add(key + "\t" + (unk ? "Unknown" : names(add)) + "\tXJAR\t" + jarNames.get(j) + "\t"
                        + jarNames.get(kc[0]) + " " + sub + "." + nd);
            }
        }
    }

    /** SOUNDNESS R1097 — the members overridden across jars beyond their row: key -> overriding classes. */
    static final TreeMap<String, TreeSet<String>> XJAR = new TreeMap<>();
    static Map<String, List<int[]>> XSUBS;
    static final List<String> XNAMES = new ArrayList<>();

    /** Every (jar k, class c) pair below each ancestor {@code a} that jar k does NOT ship, walking c's supertypes as
     *  the JVM resolves them from k ({@link #jarOf}: k's own copy first). Deterministic: jars and classes iterate in
     *  sorted order. */
    static Map<String, List<int[]>> xsubs() {
        if (XSUBS != null) return XSUBS;
        Map<String, List<int[]>> out = new HashMap<>();
        Map<String, Integer> nameId = new HashMap<>();
        for (int k = 0; k < jarClasses.size(); k++) {
            Map<String, ClassNode> m = jarClasses.get(k);
            for (ClassNode c : m.values()) {
                if ((c.access & Opcodes.ACC_INTERFACE) != 0) continue;    // an interface's default is not an override here
                ArrayDeque<String[]> q = new ArrayDeque<>();
                Set<String> seen = new HashSet<>();
                if (c.superName != null) q.add(new String[] { String.valueOf(k), c.superName });
                for (String i : c.interfaces) q.add(new String[] { String.valueOf(k), i });
                while (!q.isEmpty()) {
                    String[] x = q.poll();
                    if (!seen.add(x[1])) continue;
                    if (!m.containsKey(x[1])) {
                        Integer id = nameId.computeIfAbsent(c.name, n -> { XNAMES.add(n); return XNAMES.size() - 1; });
                        out.computeIfAbsent(x[1], a -> new ArrayList<>()).add(new int[] { k, id });
                    }
                    int aj = jarOf(Integer.parseInt(x[0]), x[1]);
                    ClassNode a = cls(aj, x[1]);
                    if (a == null) continue;
                    if (a.superName != null) q.add(new String[] { String.valueOf(aj), a.superName });
                    for (String i : a.interfaces) q.add(new String[] { String.valueOf(aj), i });
                }
            }
        }
        XSUBS = out;
        return out;
    }

    /** Closure-object dispatch the engine exempts for the same reason (Cha#isChaExemptMethod: a closure's body is
     *  attributed where the closure is CREATED, and fanning out over every closure class smears). The engine's list
     *  names {@code scala/Function*} / {@code scala/PartialFunction} {@code apply}; a Scala pattern-matching closure
     *  extends {@code scala/runtime/AbstractPartialFunction} and is invoked through {@code applyOrElse}/
     *  {@code isDefinedAt}, which it did not name. MEASURED without this: {@code AbstractPartialFunction.applyOrElse}
     *  unioned every anonymous partial function in scala-library, one of which is a {@code scala.sys.process}
     *  handler the owner rule charges Exec through its bridge (R1078's declined half) — and 8,578 scala-compiler
     *  rows gained Exec. A size bound does not stop it (scala-library declares only a handful of these closures), so
     *  a closure-object dispatch is not fanned out at all: the library's own closures reach a consumer only through
     *  the library API that built them, whose body the table already follows. */
    static boolean closureDispatch(String owner, String name) {
        boolean scala = owner.startsWith("scala/Function") || owner.equals("scala/PartialFunction")
                || owner.startsWith("scala/runtime/AbstractPartialFunction") || owner.startsWith("scala/runtime/AbstractFunction")
                || owner.startsWith("scala/runtime/java8/JFunction");
        return scala && (name.equals("apply") || name.equals("applyOrElse") || name.equals("isDefinedAt")
                || name.startsWith("apply$mc"));
    }

    static final boolean DISPATCH_ROOTS = !"off".equals(System.getProperty("framework.dispatch"));
    static final boolean DISPATCH_EDGES = "edges".equals(System.getProperty("framework.dispatch", "roots"));
    static long DISPATCH_ADDED;
    /** Keys whose row is charged ONLY through an override (the declared body charges nothing). */
    static final Set<String> OVERRIDE_ONLY = new HashSet<>();
    /** Keys whose overrides are too many to charge and can do more than the declared body (disclosed `A`). */
    static final Set<String> BROAD = new TreeSet<>();
    static final Map<String, List<String>> SUBTYPES = new HashMap<>();

    /** Every class in jar {@code j} that is a proper subtype of {@code owner} (superclass and interface edges),
     *  sorted so the table stays byte-reproducible. Memoised per (jar, owner). */
    static List<String> subtypes(int j, String owner) {
        String key = j + "|" + owner;
        List<String> m = SUBTYPES.get(key);
        if (m != null) return m;
        Map<String, List<String>> direct = DIRECT_SUBS.computeIfAbsent(j, jj -> {
            Map<String, List<String>> d = new HashMap<>();
            for (ClassNode c : jarClasses.get(jj).values()) {
                if (c.superName != null) d.computeIfAbsent(c.superName, k -> new ArrayList<>()).add(c.name);
                for (String i : c.interfaces) d.computeIfAbsent(i, k -> new ArrayList<>()).add(c.name);
            }
            return d;
        });
        TreeSet<String> out = new TreeSet<>();
        ArrayDeque<String> q = new ArrayDeque<>(direct.getOrDefault(owner, List.of()));
        while (!q.isEmpty()) { String c = q.poll(); if (out.add(c)) q.addAll(direct.getOrDefault(c, List.of())); }
        m = new ArrayList<>(out);
        SUBTYPES.put(key, m);
        return m;
    }
    static final Map<Integer, Map<String, List<String>>> DIRECT_SUBS = new HashMap<>();

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
                    // SOUNDNESS R1471 -- ANY Unknown vouches nothing, not only an Unknown-ONLY body: since the dispatch closure
                    // widened (R1303/R1304, S6) a body whose own site is Unknown reads inferred [Clock,Fs,Log,Rand,Unknown] with
                    // direct [], and the exact-[Unknown] test read it as examined-and-pure, dropping the abstract member's `A`
                    // while its concrete implementers kept their `U` (floor / UNK_ANY, line ~374).
                    // R1468: a body whose rule stand-in is disclosed rather than charged is as unvouched as it was charged
                    if (eff[t] != 0 || unkAny(t) || (LOST != null && LOST[t] != 0)) return true;
                }
            }
        }
        return bodies == 0;
    }

    /** SOUNDNESS R1468 — the concrete effects the surveyed implementers of an abstract {@code owner.name+desc} reach:
     *  the same walk as {@link #implementersUnvouched}. What an unfollowable dispatch to it can do, as far as the
     *  surveyed jars say; an implementer outside them is the reason the dispatch is disclosed at all. */
    static int implementersMask(String owner, String name, String desc, int[] eff) {
        implementersUnvouched(owner, name, desc, eff);    // builds `subs`
        ArrayDeque<String> q = new ArrayDeque<>(subs.getOrDefault(owner, List.of()));
        Set<String> seen = new HashSet<>();
        int m = 0;
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            q.addAll(subs.getOrDefault(c, List.of()));
            List<Integer> js = classJars.get(c);
            if (js == null) continue;
            for (int j : js) {
                ClassNode cn = cls(j, c);
                if (cn == null || (cn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE)) != 0) continue;
                for (int t : resolve(j, c, name, desc)) m |= eff[t];
            }
        }
        return m;
    }

    /** SOUNDNESS R1468 — whether {@code owner} or a supertype the surveyed jars ship declares {@code nameDesc} (so a call
     *  that resolves to no body is an abstract member's dispatch, not a JDK method the surveyed class inherits). */
    static boolean declaredInUniverse(int from, String owner, String nameDesc) {
        ArrayDeque<String> q = new ArrayDeque<>(); q.add(owner);
        Set<String> seen = new HashSet<>();
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            ClassNode cn = cls(jarOf(from, c), c);
            if (cn == null) continue;
            for (MethodNode mn : cn.methods) if ((mn.name + mn.desc).equals(nameDesc)) return true;
            if (cn.superName != null) q.add(cn.superName);
            q.addAll(cn.interfaces);
        }
        return false;
    }

    /** SOUNDNESS R1468 — per body, the step-5a rule stand-in it DISCLOSES instead of charging (no implementer of an
     *  unfollowable dispatch in its closure carries that effect), and the least unfollowable member of its closure,
     *  which the disclosure names. Null until step 5a has run. */
    static int[] LOST;
    static String[] OPAQUE_REP;
    /** Consumer-facing members whose row lost a stand-in: key -> the unfollowable member the `C` line names. */
    static final TreeMap<String, String> CLOSURE = new TreeMap<>();
    static final Map<String, Integer> CLOSURE_LOST = new HashMap<>();

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
                List<Integer> r = resolve(j, m.owner, m.name, m.desc);
                out.addAll(r);
                // SOUNDNESS R1096 — a VIRTUAL call runs whichever surveyed override the receiver selects (EDGES mode).
                if (DISPATCH_EDGES && (m.getOpcode() == Opcodes.INVOKEVIRTUAL || m.getOpcode() == Opcodes.INVOKEINTERFACE))
                    out.addAll(overriders(j, m.owner, m.name, m.desc, r));
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
