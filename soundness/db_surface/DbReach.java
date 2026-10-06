package io.poly.candor;   // compiled by soundness/db_surface/derive.sh against the engine jar; not part of the build
import java.io.*; import java.nio.file.*; import java.util.*; import java.util.stream.*;
import org.objectweb.asm.*; import org.objectweb.asm.tree.*;
import io.poly.candor.model.Effect;
/** Args: <classesDir> <sinkPrefixes,...> <apiTypePrefixes,...> [maxDepth]
 *  Per public member of each public API type: Classifier verdict, and whether ANY concrete implementation
 *  reaches a call whose owner.name starts with a sink prefix (the client's wire choke point), over a CHA call
 *  graph built from the tree's bytecode. Prints the first path found. */
public class DbReach {
  static Map<String, ClassNode> cn = new HashMap<>();
  static Map<String, List<String>> subs = new HashMap<>();
  static String[] sinks; static int MAXD = 14;
  static Map<String, String> memo = new HashMap<>();   // key -> path or "" (no)
  public static void main(String[] a) throws Exception {
    try (Stream<Path> s = Files.walk(Paths.get(a[0]))) { for (Path p : s.filter(x -> x.toString().endsWith(".class")).collect(Collectors.toList())) {
      ClassNode c = new ClassNode(); try (InputStream in = Files.newInputStream(p)) { new ClassReader(in).accept(c, 0); } catch (Exception e) { continue; }
      cn.put(c.name, c); } }
    for (ClassNode c : cn.values()) { if (c.superName != null) subs.computeIfAbsent(c.superName, k -> new ArrayList<>()).add(c.name);
      for (String i : c.interfaces) subs.computeIfAbsent(i, k -> new ArrayList<>()).add(c.name); }
    sinks = a[1].split(","); String[] pfx = a[2].split(","); if (a.length > 3) MAXD = Integer.parseInt(a[3]);
    for (ClassNode t : new TreeMap<>(cn).values()) {
      if ((t.access & Opcodes.ACC_PUBLIC) == 0) continue;
      boolean api = false; for (String p : pfx) if (t.name.startsWith(p)) api = true;
      if (!api || t.name.contains("/internal/") || t.name.contains("$")) continue;
      System.err.println("#SUPER\t" + t.name + "\t" + (t.superName == null ? "" : t.superName) + "," + String.join(",", t.interfaces));
      Map<String, String> members = new TreeMap<>(); collect(t.name, members, new HashSet<>());
      for (String nd : members.keySet()) {
        int p = nd.indexOf('('); String name = nd.substring(0, p), desc = nd.substring(p);
        Effect ef = Classifier.classify(t.name.replace('/', '.'), name, desc);
        int n = 0; String path = null;
        for (String c : concreteSubs(t.name)) { MethodNode mn = resolveM(c, name, desc); if (mn == null) continue; n++;
          String r = reach(owner(mn), mn, 0, new HashSet<>()); if (r != null) { path = r; break; } }
        Type rt = Type.getReturnType(desc);
        String rn = rt.getSort() == Type.OBJECT ? rt.getInternalName() : "";
        boolean lazy = !rn.isEmpty() && lazyType(rn, new HashSet<>());
        String lazyKind = "";
        if (lazy) {
          if (rn.startsWith("reactor/") || rn.startsWith("io/reactivex/") || rn.equals("org/reactivestreams/Publisher")) lazyKind = "LAZY";
          else if (cn.containsKey(rn)) { boolean fam = false; for (String p2 : pfx) if (rn.startsWith(p2)) fam = true; lazyKind = fam ? "LAZY" : ""; }
          else {
            // A bare JDK collection/iterator/stream: a live VIEW only if an implementation allocates an in-tree
            // class that is itself lazy (RedissonMap's key set); a JDK collection it builds is a snapshot.
            boolean view = false;
            for (String c : concreteSubs(t.name)) { MethodNode mn = resolveM(c, name, desc); if (mn == null || mn.instructions == null) continue;
              for (AbstractInsnNode in : mn.instructions) if (in instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW
                  && cn.containsKey(ti.desc) && lazyType(ti.desc, new HashSet<>())) view = true; }
            lazyKind = view ? "JDKVIEW:" + rn : "";
          }
        }
        System.out.println(t.name + "\t" + nd + "\t" + ef + "\t" + (n == 0 ? "NOIMPL" : path != null ? "WIRE" : "local") + "\t" + (path == null ? "" : path) + "\t" + lazyKind);
      }
    }
  }
  static Map<MethodNode, String> ownerOf = new IdentityHashMap<>();
  static String owner(MethodNode m) { return ownerOf.get(m); }
  static Map<String, String> wire = null;   // method key -> next hop toward a sink
  static String key(String own, MethodNode m) { return own + "." + m.name + m.desc; }
  static void build() {
    Map<String, List<String>> rev = new HashMap<>();   // callee key -> caller keys
    Deque<String> q = new ArrayDeque<>(); wire = new HashMap<>();
    for (ClassNode c : cn.values()) for (MethodNode mn : c.methods) {
      if (mn.instructions == null) continue; String me = key(c.name, mn);
      for (AbstractInsnNode in : mn.instructions) {
        if (in instanceof InvokeDynamicInsnNode id) {
          for (Object ba : id.bsmArgs) if (ba instanceof Handle h) {
            String t2 = h.getOwner() + "." + h.getName(); boolean sk = false; for (String s : sinks) if (t2.startsWith(s)) sk = true;
            if (sk) { if (!wire.containsKey(me)) { wire.put(me, t2); q.add(me); } continue; }
            MethodNode hb = resolveM(h.getOwner(), h.getName(), h.getDesc());
            if (hb != null) rev.computeIfAbsent(key(owner(hb), hb), k -> new ArrayList<>()).add(me);
          }
          continue;
        }
        if (!(in instanceof MethodInsnNode m)) continue;
        String tgt = m.owner + "." + m.name;
        boolean sink = false; for (String s : sinks) if (tgt.startsWith(s)) sink = true;
        // An in-tree INTERFACE/abstract call with NO concrete implementer in the tree (a dynamic proxy, a user
        // SPI) or a reflective invoke is OPAQUE: the instrument cannot prove it stays off the wire, so it
        // counts as reaching it. This keeps the derived PURE set from inheriting the instrument's blind spots.
        if (!sink && (tgt.equals("java/lang/reflect/Method.invoke") || tgt.equals("java/lang/reflect/InvocationHandler.invoke")
                || (m.getOpcode() == Opcodes.INVOKEINTERFACE && cn.containsKey(m.owner) && resolveM(m.owner, m.name, m.desc) == null
                    && concreteSubs(m.owner).stream().noneMatch(cc2 -> resolveM(cc2, m.name, m.desc) != null)))) { sink = true; tgt = "OPAQUE:" + tgt; }
        if (sink) { if (!wire.containsKey(me)) { wire.put(me, tgt); q.add(me); } continue; }
        List<String> callees = new ArrayList<>();
        MethodNode b = resolveM(m.owner, m.name, m.desc); if (b != null) callees.add(key(owner(b), b));
        if (m.getOpcode() != Opcodes.INVOKESTATIC && m.getOpcode() != Opcodes.INVOKESPECIAL && cn.containsKey(m.owner))
          for (String cc : concreteSubs(m.owner)) { MethodNode bb = resolveM(cc, m.name, m.desc); if (bb != null) callees.add(key(owner(bb), bb)); }
        for (String ce : callees) rev.computeIfAbsent(ce, k -> new ArrayList<>()).add(me);
      }
    }
    while (!q.isEmpty()) { String x = q.poll(); for (String caller : rev.getOrDefault(x, List.of())) if (!wire.containsKey(caller)) { wire.put(caller, x); q.add(caller); } }
  }
  static String reach(String own, MethodNode mn, int d, Set<String> stack) {
    if (wire == null) build();
    String k = key(own, mn); if (!wire.containsKey(k)) return null;
    StringBuilder sb = new StringBuilder(); String x = k; int n = 0;
    while (x != null && n++ < 30) { sb.append(x.substring(x.lastIndexOf('/') + 1).replaceAll("\\(.*", "")).append(">"); x = wire.get(x); if (x != null && !wire.containsKey(x)) { sb.append(x); break; } }
    return sb.toString();
  }
  /** A type whose consumption runs through an interface the classifier cannot charge: the JDK's iteration,
   *  collection, stream and I/O interfaces, and reactive publishers (subscription runs the query). */
  static final String[] LAZY_ROOTS = { "java/lang/Iterable", "java/util/Iterator", "java/util/Map", "java/util/Collection",
      "java/util/stream/BaseStream", "java/io/InputStream", "java/io/OutputStream", "java/io/Reader", "java/io/Writer",
      "java/nio/channels/Channel", "org/reactivestreams/Publisher", "java/util/concurrent/Flow$Publisher",
      "java/util/Spliterator", "java/util/Enumeration" };
  static boolean lazyType(String t, Set<String> seen) {
    if (t == null || !seen.add(t)) return false;
    for (String r : LAZY_ROOTS) if (t.equals(r)) return true;
    if (t.startsWith("reactor/core/publisher/") || t.startsWith("io/reactivex/") || t.startsWith("java/util/stream/")
        || t.equals("java/util/ListIterator") || t.equals("java/lang/AutoCloseable") && false) return true;
    if (t.startsWith("java/util/") && (t.endsWith("List") || t.endsWith("Set") || t.endsWith("Map") || t.endsWith("Queue") || t.endsWith("Deque") || t.endsWith("Collection"))) return true;
    ClassNode c = cn.get(t); if (c == null) return false;
    if (lazyType(c.superName, seen)) return true;
    for (String i : c.interfaces) if (lazyType(i, seen)) return true;
    return false;
  }
  static void collect(String t, Map<String, String> out, Set<String> seen) {
    if (t == null || !seen.add(t) || t.equals("java/lang/Object")) return;
    ClassNode c = cn.get(t); if (c == null) return;
    for (MethodNode mm : c.methods) {
      if ((mm.access & Opcodes.ACC_SYNTHETIC) != 0 || (mm.access & Opcodes.ACC_STATIC) != 0) continue;
      if (mm.name.startsWith("<")) continue;
      out.putIfAbsent(mm.name + mm.desc, t);
    }
    collect(c.superName, out, seen); for (String i : c.interfaces) collect(i, out, seen);
  }
  static Map<String, Set<String>> csMemo = new HashMap<>();
  static Set<String> concreteSubs(String t) {
    return csMemo.computeIfAbsent(t, tt -> { Set<String> out = new TreeSet<>(); Deque<String> q = new ArrayDeque<>(List.of(tt)); Set<String> seen = new HashSet<>();
      while (!q.isEmpty()) { String x = q.poll(); if (!seen.add(x)) continue; ClassNode c = cn.get(x);
        if (c != null && (c.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) == 0) out.add(x);
        q.addAll(subs.getOrDefault(x, List.of())); }
      return out; });
  }
  static MethodNode resolveM(String c, String name, String desc) {
    for (String x = c; x != null; ) { ClassNode k = cn.get(x); if (k == null) break;
      for (MethodNode mm : k.methods) if (mm.name.equals(name) && mm.desc.equals(desc) && (mm.access & Opcodes.ACC_ABSTRACT) == 0) { ownerOf.put(mm, x); return mm; }
      x = k.superName; }
    Deque<String> q = new ArrayDeque<>(); q.add(c); Set<String> seen = new HashSet<>();
    while (!q.isEmpty()) { String x = q.poll(); if (!seen.add(x)) continue; ClassNode k = cn.get(x); if (k == null) continue;
      if ((k.access & Opcodes.ACC_INTERFACE) != 0) for (MethodNode mm : k.methods) if (mm.name.equals(name) && mm.desc.equals(desc) && (mm.access & Opcodes.ACC_ABSTRACT) == 0) { ownerOf.put(mm, x); return mm; }
      if (k.superName != null) q.add(k.superName); q.addAll(k.interfaces); }
    return null;
  }
}
