package io.poly.candor;

import java.util.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;
import io.poly.candor.model.Effect;
import static io.poly.candor.AnalysisState.ctx;

/**
 * SOUNDNESS R825 — WHERE A RUNTIME-LOADED QUERY HANDLE GOES, FOLLOWED FORWARD, FAIL-CLOSED.
 *
 * <p><b>The defect this replaces.</b> A query builder the classifier leaves pure ({@code
 * em.createNativeQuery(sql)}, {@code st.addBatch(sql)}, {@code dsl.resultQuery(sql)}) loads a runtime String
 * into a HANDLE, and a zero-argument terminal ({@code getResultList()}, {@code executeBatch()}, {@code
 * fetch()}) later runs it. v0.39.2 marked the builder unconditionally (fail-closed, but it also marked
 * {@code new SQLException(msg)}, 17,436 rows over 372 jars). R794 keyed the mark on the Db call and then
 * R794b/R819/R824 added hops by which a handle is traced from load to terminal — receiver chains, helper
 * returns, parameters, fields, containers. Every one of those was a way to REACH a terminal, and the mark
 * fired only when a trace SUCCEEDED, so every shape the tracer did not model was SILENT: 17 shapes executed
 * on H2 ({@code Objects.requireNonNull(prep(c,sql)).executeBatch()}, {@code Optional.ofNullable(..)
 * .orElseThrow()}, a lambda capture, {@code q::getResultList}, a record component, a static container
 * filled by a helper, …) exited 1 on v0.39.2 and 0 at 5f695f9. The default had gone from closed to open.
 *
 * <p><b>What this pass is NOT (SOUNDNESS R840).</b> R825 shipped it as a fail-closed replacement for the
 * 0.39.2 mark. It is not one. A re-review executed ten shapes that 0.39.2 marks and this pass alone did not,
 * because every rule below that declines to mark is correct only if some list is complete, and none is. So
 * the 0.39.2 mark is restored in {@code Candor} as the FLOOR, and this pass only ADDS: it marks the frames
 * that EXECUTE a handle loaded somewhere else (a field read, a helper's return, a callee handed the handle),
 * which 0.39.2 never marked. Nothing here can remove a mark, so no shape 0.39.2 discloses can go silent.
 *
 * <p><b>The non-marking rules, and the list each one depends on.</b> Beyond the floor, each fails SILENT when
 * its list is incomplete:
 * <ul><li>(1) A call the classifier does not charge {@code Db}, made on a handle owned by a SQL-bearing type,
 * is taken as a BUILDER STEP. This depends on the terminal classifier being complete. It is not: jOOQ
 * {@code stream()}/{@code collect()}/{@code executeAsync} and Hibernate {@code uniqueResultOptional}/
 * {@code getResultStream}/{@code getSingleResultOrNull}/{@code getResultCount}.</li>
 * <li>(2) {@link #isCarrier} owners store the handle and hand it back only through their receiver or result.
 * This depends on the carrier list, and it is false for {@code CompletableFuture}, whose dependents run inside
 * {@code complete()}. Carrier calls also do not fan out to PROJECT implementors of the declaration, so a
 * project {@code Map} or {@code Flow.Subscriber} that runs the handle is missed.</li>
 * <li>(3) Only fields of a handle-capable declared type are keyed globally. An {@code Object}-typed generic
 * {@code Box<T>.v}, a raw field or a {@code SoftReference} reached through another field drops the taint.</li>
 * <li>(4) Loggers and {@code java.io} are sinks.</li>
 * <li>(5) CHA stops after 17 bodies ({@link Candor#dbProjectBodies}), and at the cap this pass marks.</li>
 * <li>(6) Summaries stop at depth {@value #MAX_DEPTH}.</li>
 * <li>(7) A handle returned out of the scan, or stored in a field with no in-scan reader, reaches no mark
 * here. For a CHAINED consumer the floor covers the storing function, whose own report carries the mark.</li></ul>
 * Rules (5) and (6) mark on truncation. The others are allow-shaped. Each has an executed fixture in this
 * repository's R840 evidence showing it silent in an EXECUTING frame; the same shape is silent on v0.39.2 too.
 *
 * <p><b>Where the mark lands.</b> On a frame that executes a handle this pass followed there, on a frame that
 * passes a handle into a callee whose summary executes it, and on the frame where this pass lost the handle
 * (depth, no body, a library call). R841: seeding once took every String-carrying {@code org/hibernate/}-style
 * call as a loader, and 13 of 22 audited marks were not query handles. Seeds are now limited to results of a
 * type some {@code Db} call in the program runs or is handed.
 */
final class DbHandleFlow {

    /** A per-parameter (or per-receiver) answer about one body: does a handle arriving in that slot get
     *  executed or lost ({@code why}), returned, stored into the receiver, or stored into another parameter. */
    static final class Summ {
        String why;    // a SEEN execution — the only thing that marks
        String lost;   // where the handle was lost instead — REACH only, never a mark (R840/R841)
        boolean returns, intoRecv;
        final BitSet intoParams = new BitSet();
    }

    /** Result types that are provably not a handle and cannot hold one — a VALUE. Taint does not flow into
     *  them. A DENYLIST: an unlisted type carries taint, which can only over-mark. */
    static final Set<String> NON_HOLDER = Set.of(
            "java/lang/String", "java/lang/CharSequence", "java/lang/Integer", "java/lang/Long",
            "java/lang/Short", "java/lang/Byte", "java/lang/Boolean", "java/lang/Double", "java/lang/Float",
            "java/lang/Character", "java/lang/Number", "java/math/BigDecimal", "java/math/BigInteger",
            "java/lang/StringBuilder", "java/lang/StringBuffer", "java/lang/Class");

    /** Result types that are a FACTORY or EXECUTOR of queries, never a container of one: a statement's
     *  {@code getConnection()} is not the statement, and running {@code commit()} on it runs nothing that
     *  was loaded. Also the value types {@link Candor#DB_NON_HANDLE_TYPES} names (a {@code java.sql.Array}
     *  from {@code createArrayOf(type, xs)} is a bound VALUE — the R794 partition's over-follow). A
     *  DENYLIST: a factory type not listed here carries taint, which over-marks. */
    static final Set<String> NON_HANDLE = new HashSet<>();
    static {
        NON_HANDLE.addAll(Candor.DB_NON_HANDLE_TYPES);
        NON_HANDLE.addAll(List.of("java/sql/Connection", "javax/sql/DataSource", "javax/sql/XAConnection",
                "javax/sql/PooledConnection", "java/sql/DatabaseMetaData", "java/sql/ResultSetMetaData",
                "java/sql/ParameterMetaData", "java/sql/Savepoint",
                "jakarta/persistence/EntityManager", "javax/persistence/EntityManager",
                "jakarta/persistence/EntityManagerFactory", "javax/persistence/EntityManagerFactory",
                "jakarta/persistence/EntityTransaction", "javax/persistence/EntityTransaction",
                "org/hibernate/Session", "org/hibernate/SessionFactory", "org/hibernate/StatelessSession",
                "org/hibernate/Transaction", "org/jooq/DSLContext", "org/jooq/Configuration",
                "io/r2dbc/spi/Connection", "io/r2dbc/spi/ConnectionFactory",
                // The PRODUCT of an execution, not a query: the query ran at the call that returned it, and
                // that call is where the mark lands. Reading its rows runs nothing new. Tracked as a handle,
                // one proxy ResultSet made every `rs.next()` in hazelcast inherit a hedge through CHA (31,762
                // rows from 147 marks).
                "java/sql/ResultSet", "javax/sql/RowSet", "javax/sql/rowset/CachedRowSet",
                "javax/sql/rowset/JdbcRowSet", "org/jooq/Result", "org/jooq/Record", "org/jooq/Cursor",
                "io/r2dbc/spi/Result", "io/r2dbc/spi/Row", "org/hibernate/ScrollableResults"));
    }

    private final AnalysisContext ctx;
    private final Map<MethodNode, ClassNode> ownerOf = new IdentityHashMap<>();
    private final Map<String, MethodNode> byId = new HashMap<>();
    private final Map<String, List<MethodNode>> callersByNameDesc = new HashMap<>();
    private final Map<String, List<MethodNode>> fieldReaders = new HashMap<>();
    private final Map<String, Set<String>> siteOwners = new HashMap<>();
    private final Map<String, List<MethodNode>> indyUsersByImpl = new HashMap<>();
    private final Set<String> handleTypes = new HashSet<>();
    /** The types a LOADER in this program produces (its result, or a void loader's receiver): the only
     *  declared types, besides containers and function values, a field is keyed globally by. Keying on every
     *  SQL-bearing type made each `org.hibernate` field global in hibernate's own scan (89,207 seeds). */
    private final Set<String> sourceTypes = new HashSet<>();
    private final Set<String> taintedFields = new HashSet<>();
    private final Set<MethodNode> returnsTainted = Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<MethodNode, BitSet> outParams = new IdentityHashMap<>();
    private final Map<MethodNode, Map<Integer, Summ>> summaries = new IdentityHashMap<>();
    private final Set<String> inProgress = new HashSet<>();
    private boolean provisional;   // a summary consulted an in-progress one or hit the depth bound: don't cache
    private final Deque<MethodNode> queue = new ArrayDeque<>();
    private final Set<MethodNode> queued = Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<MethodNode, String> marked = new IdentityHashMap<>();
    static final int MAX_DEPTH = 6;
    /** Summaries computed per scan before the follower stops. It only ADDS marks over the 0.39.2 floor, so
     *  stopping early loses additions, never a floor mark; the stop is printed. */
    static final int WORK_BUDGET = 200_000;
    private int work;
    private static final class Budget extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Budget() { super("DbHandleFlow work budget exhausted", null, false, false); }
    }

    private DbHandleFlow(AnalysisContext ctx) { this.ctx = ctx; }

    /** Run over the whole scanned program, after every class has been analysed and before the fixpoint.
     *  Only ever ADDS {@code incomplete: [Db]}. */
    static void run(List<ClassNode> classes) {
        DbHandleFlow f = new DbHandleFlow(ctx());
        try {
            f.go(classes);
        } catch (RuntimeException | StackOverflowError e) {
            // The pass could not finish, so nothing it would have proven is proven: every body holding a
            // loader is marked, which is v0.39.2's answer. Never silent, and never a lost scan.
            System.err.println("candor-java: Db handle flow failed (" + e + "); marking every loader body");
            f.failClosed(classes);
        }
    }

    private void failClosed(List<ClassNode> classes) {
        for (ClassNode cn : classes) {
            if (cn.methods == null) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode in : mn.instructions)
                    if (in instanceof MethodInsnNode m && Candor.isSqlBearingOwner(m.owner) && !"<init>".equals(m.name)
                            && m.desc.contains("Ljava/lang/String;") && !Candor.isSqlParameterBinder(m.name)) {
                        ctx.surfaceIncomplete.computeIfAbsent(Cha.methodId(cn.name.replace('/', '.'), mn.name, mn.desc),
                                x -> new TreeSet<>()).add("Db");
                        break;
                    }
            }
        }
    }

    /** Is {@code why} a SEEN execution (its last hop ran a Db call on the handle), not a loss? */
    static boolean seenExec(String why) {
        String last = why.substring(why.lastIndexOf('>') + 1);
        return last.startsWith("exec:") || last.startsWith("bound-exec:") || last.startsWith("callback-exec:");
    }

    static final boolean TRACE = System.getenv("CANDOR_R825_TRACE") != null;
    private static String describe(Object o) {
        if (o instanceof MethodInsnNode m) return "call " + m.owner + "." + m.name + m.desc;
        if (o instanceof FieldInsnNode f) return "field " + f.owner + "." + f.name;
        if (o instanceof InvokeDynamicInsnNode i) return "indy " + i.name;
        return String.valueOf(o);
    }

    private String nameOf(MethodNode b) {
        ClassNode cn = ownerOf.get(b);
        return (cn == null ? "?" : cn.name) + "." + b.name;
    }

    private void go(List<ClassNode> classes) {
        List<MethodNode> candidates = new ArrayList<>();
        List<Object[]> typedCandidates = new ArrayList<>();   // {mn, returnType} — a non-SQL loader, decided below
        for (ClassNode cn : classes) {
            if (cn.methods == null) continue;
            String dotted = cn.name.replace('/', '.');
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                ownerOf.put(mn, cn);
                byId.put(Cha.methodId(dotted, mn.name, mn.desc), mn);
                boolean cand = false;
                for (AbstractInsnNode in : mn.instructions) {
                    if (in instanceof MethodInsnNode m) {
                        callersByNameDesc.computeIfAbsent(m.name + m.desc, k -> new ArrayList<>()).add(mn);
                        siteOwners.computeIfAbsent(m.name + m.desc, k -> new HashSet<>()).add(m.owner);
                        boolean hasString = m.desc.contains("Ljava/lang/String;");
                        if (hasString && Candor.isSqlBearingOwner(m.owner) && !Candor.isSqlParameterBinder(m.name)
                                && !(ctx.projectClasses.contains(m.owner) && !bodiesOf(m).isEmpty())) {
                            cand = true;
                            Type rt = Type.getReturnType(m.desc);
                            if (rt.getSort() == Type.OBJECT) sourceTypes.add(rt.getInternalName());
                            else if (rt.getSort() == Type.VOID && m.getOpcode() != Opcodes.INVOKESTATIC) sourceTypes.add(m.owner);
                        }
                        else if (hasString) {
                            Type rt = Type.getReturnType(m.desc);
                            if (rt.getSort() == Type.OBJECT) typedCandidates.add(new Object[]{mn, rt.getInternalName()});
                        }
                        // The receiver type of every Db-classified INSTANCE call: a value of that type is
                        // something a terminal runs, so a runtime String loaded into one is a locator.
                        if (!"<init>".equals(m.name)
                                && Classifier.classify(m.owner.replace('/', '.'), m.name, m.desc) == Effect.DB) {
                            if (m.getOpcode() != Opcodes.INVOKESTATIC) handleTypes.add(m.owner);
                            // …and the declared type of every object a Db call is HANDED (`session.execute(stmt)`).
                            for (Type at : Type.getArgumentTypes(m.desc))
                                if (at.getSort() == Type.OBJECT) handleTypes.add(at.getInternalName());
                        }
                    } else if (in instanceof FieldInsnNode fi && (fi.getOpcode() == Opcodes.GETFIELD
                            || fi.getOpcode() == Opcodes.GETSTATIC)) {
                        fieldReaders.computeIfAbsent(fkey(fi), k -> new ArrayList<>()).add(mn);
                    } else if (in instanceof InvokeDynamicInsnNode idin) {
                        Handle h = implHandle(idin);
                        if (h != null) {
                            indyUsersByImpl.computeIfAbsent(h.getOwner() + "." + h.getName() + h.getDesc(),
                                    k -> new ArrayList<>()).add(mn);
                            if (Candor.isSqlBearingOwner(h.getOwner()) && h.getDesc().contains("Ljava/lang/String;")
                                    && !Candor.isSqlParameterBinder(h.getName())) cand = true;
                        }
                    }
                }
                if (cand) candidates.add(mn);
            }
        }
        handleTypes.removeAll(NON_HANDLE);
        for (Object[] tc : typedCandidates)
            if (handleTypes.contains((String) tc[1])) { candidates.add((MethodNode) tc[0]); sourceTypes.add((String) tc[1]); }
        sourceTypes.removeAll(NON_HANDLE);
        sourceTypes.removeAll(NON_HOLDER);
        sourceTypes.remove("java/lang/Object");
        if (candidates.isEmpty()) return;
        for (MethodNode mn : candidates) enqueue(mn);
        try {
            while (!queue.isEmpty()) {
                MethodNode mn = queue.poll();
                queued.remove(mn);
                definite(mn);
            }
        } catch (Budget b) {
            System.err.println("candor-java: Db handle follower stopped at its work budget (" + WORK_BUDGET
                    + " summaries); the marks it found are kept, and the 0.39.2 floor is unaffected");
        }
        for (Map.Entry<MethodNode, String> e : marked.entrySet()) {
            ClassNode cn = ownerOf.get(e.getKey());
            String id = Cha.methodId(cn.name.replace('/', '.'), e.getKey().name, e.getKey().desc);
            // SOUNDNESS R840/R841 — only a SEEN execution marks. A handle this pass LOST (a library call, an
            // interface with no implementor, the depth or CHA bound, a return into library dispatch) used to
            // mark too, as a fail-closed escape; audited, 13 of 22 such marks were not query handles at all
            // (R841), and the escapes never made the pass fail closed anyway (R840) — the 0.39.2 floor in
            // Candor is what does that now. A lost handle is printed for REACH, and marks nothing.
            String last = e.getValue().substring(e.getValue().lastIndexOf('>') + 1);
            boolean seen = last.startsWith("exec:") || last.startsWith("bound-exec:") || last.startsWith("callback-exec:");
            if (!seen) {
                if (Candor.MASK_DEBUG) System.err.println("R825LOST\t" + id + "\t" + e.getValue());
                continue;
            }
            ctx.surfaceIncomplete.computeIfAbsent(id, x -> new TreeSet<>()).add("Db");
            if (Candor.MASK_DEBUG) System.err.println("R825MARK\t" + id + "\t" + e.getValue());
        }
    }

    private void enqueue(MethodNode mn) {
        if (mn != null && queued.add(mn)) queue.add(mn);
    }

    // ── sources ──────────────────────────────────────────────────────────────────────────────────────

    /** Is {@code m} a call that LOADS a runtime String into a query handle? Its result is the handle, or
     *  (a void call) its receiver is. The owner must be SQL-bearing, or its result a type some Db call in
     *  this program runs ({@link #handleTypes}: {@code db.getCollection(name)} → {@code MongoCollection}).
     *
     *  <p>NOT a loader, each by a stated property: a JDBC/JPA parameter BINDER ({@code set*}: a value, never
     *  the query); a result that is a VALUE or a FACTORY ({@link #NON_HANDLE}: {@code rs.getString(col)},
     *  {@code createArrayOf(type, xs)}, {@code DriverManager.getConnection(url)} — the URL names the database,
     *  not a table); a constructor of a THROWABLE ({@code new SQLException(msg)}, v0.39.2's 17,436 rows);
     *  a void call on a {@code ResultSet} (its String is a column label). */
    private boolean isLoader(Frame<SourceValue>[] fr, InsnList insns, MethodInsnNode m) {
        // A builder this scan HAS the body of is not a loader here: its String reaches the driver inside
        // visible code, where the JDBC/driver call carrying it is marked by the per-call Db rule and the mark
        // climbs the call graph. The loader rule exists to bridge a body the scan cannot see. Measured: kept,
        // hibernate-core's own scan seeded every internal `org.hibernate` call taking an entity or type NAME
        // (6,879 marks, led by `JavaTypeRegistry.resolveDescriptor`). An owner that is
        // project-named but has no concrete body (an API interface compiled into the scan) is still a loader.
        if (ctx.projectClasses.contains(m.owner) && !bodiesOf(m).isEmpty()) return false;
        boolean sql = Candor.isSqlBearingOwner(m.owner);
        if (sql && Candor.isSqlParameterBinder(m.name)) return false;
        if (!m.desc.contains("Ljava/lang/String;")) return false;
        if ("<init>".equals(m.name)) {
            if (!sql || isThrowableName(m.owner)) return false;
            return Candor.runtimeStringSlot(fr, insns, m) >= 0;
        }
        Type rt = Type.getReturnType(m.desc);
        if (rt.getSort() == Type.VOID) {
            if (!sql || m.getOpcode() == Opcodes.INVOKESTATIC) return false;
            if (m.owner.equals("java/sql/ResultSet")) return false;
            if (!handleTypes.contains(m.owner)) return false;   // R841: a receiver no Db call in the program runs
            return Candor.runtimeStringSlot(fr, insns, m) >= 0;
        }
        if (rt.getSort() != Type.OBJECT && rt.getSort() != Type.ARRAY) return false;
        String rn = rt.getSort() == Type.OBJECT ? rt.getInternalName() : "";
        if (NON_HANDLE.contains(rn) || NON_HOLDER.contains(rn) || rn.equals("java/lang/Object")) return false;
        // SOUNDNESS R841 — the result must be a type some Db call in this program RUNS (or is handed). The
        // `org/hibernate/` etc. owner prefix alone seeded `AnnotationDescriptor.getAttribute(String)`, result
        // assemblers and value lists — 13 of 22 audited marks. This narrows only what the FOLLOWER adds: the
        // load frame is marked by the 0.39.2 floor in Candor regardless (R840).
        if (!handleTypes.contains(rn)) return false;
        return Candor.runtimeStringSlot(fr, insns, m) >= 0;
    }

    private static boolean isThrowableName(String owner) {
        return owner.endsWith("Exception") || owner.endsWith("Error") || owner.endsWith("Warning")
                || owner.endsWith("Throwable");
    }

    /** A method reference to a loader ({@code em::createNativeQuery}): the String arrives when the
     *  function is applied, from wherever the caller's stream holds it — runtime by construction. */
    private boolean isLoaderRef(Handle h) {
        return h != null && projectBody(h.getOwner(), h.getName(), h.getDesc()) == null && Candor.isSqlBearingOwner(h.getOwner()) && !Candor.isSqlParameterBinder(h.getName())
                && h.getDesc().contains("Ljava/lang/String;") && Type.getReturnType(h.getDesc()).getSort() == Type.OBJECT
                && !NON_HANDLE.contains(Type.getReturnType(h.getDesc()).getInternalName());
    }

    // ── the definite pass over one body ───────────────────────────────────────────────────────────────

    private void definite(MethodNode mn) {
        Frame<SourceValue>[] fr = Candor.srcFramesOf(mn);
        InsnList insns = mn.instructions;
        if (fr == null) {
            // No frames: nothing below can be proven, so a body that holds a loader is marked (fail-closed).
            for (AbstractInsnNode in : insns)
                if (in instanceof MethodInsnNode m && Candor.isSqlBearingOwner(m.owner)
                        && m.desc.contains("Ljava/lang/String;") && !Candor.isSqlParameterBinder(m.name)) {
                    mark(mn, "no-frames");
                    return;
                }
            return;
        }
        boolean inst = (mn.access & Opcodes.ACC_STATIC) == 0;
        Set<Object> seeds = new HashSet<>();
        for (int j = 0; j < insns.size(); j++) {
            AbstractInsnNode in = insns.get(j);
            if (fr[j] == null) continue;
            if (in instanceof MethodInsnNode m) {
                if (isLoader(fr, insns, m)) {
                    if ("<init>".equals(m.name) || Type.getReturnType(m.desc).getSort() == Type.VOID) {
                        SourceValue rv = receiverOf(fr[j], m);
                        if (rv != null) for (Object r : roots(fr, insns, rv))
                            if (!(inst && r instanceof Integer s0 && s0 == 0)) seeds.add(r);
                    } else seeds.add(m);
                    continue;
                }
                // Only a call DISPATCHED ON A PROJECT TYPE picks up a project body's returned handle. Through a
                // library interface (`Iterator.next()`, `Function.apply()`) CHA reaches every project
                // implementor in the program, and one of them returning a handle would seed every such call
                // site anywhere — measured: 139,243 seeds in hazelcast alone. Such an implementor is marked
                // itself instead (see {@link #definite}), and a tainted RECEIVER is followed by the carrier rule.
                List<MethodNode> bodies = ctx.projectClasses.contains(m.owner) ? bodiesOf(m) : List.of();
                boolean ret = false;
                for (MethodNode b : bodies) {
                    if (returnsTainted.contains(b)) ret = true;
                    BitSet op = outParams.get(b);
                    if (op != null) for (int p = op.nextSetBit(0); p >= 0; p = op.nextSetBit(p + 1)) {
                        SourceValue av = operand(fr[j], m, p);
                        if (av != null) for (Object r : roots(fr, insns, av))
                            if (!(inst && r instanceof Integer s0 && s0 == 0)) seeds.add(r);
                    }
                }
                if (ret && holder(Type.getReturnType(m.desc))) seeds.add(m);
            } else if (in instanceof FieldInsnNode fi && (fi.getOpcode() == Opcodes.GETFIELD
                    || fi.getOpcode() == Opcodes.GETSTATIC) && taintedFields.contains(fkey(fi))) {
                seeds.add(fi);
            } else if (in instanceof InvokeDynamicInsnNode idin) {
                Handle h = implHandle(idin);
                if (isLoaderRef(h)) seeds.add(idin);
                else {
                    MethodNode b = h == null ? null : projectBody(h.getOwner(), h.getName(), h.getDesc());
                    if (b != null && returnsTainted.contains(b)) seeds.add(idin);
                }
            }
        }
        if (seeds.isEmpty()) return;
        if (TRACE) for (Object o : seeds) System.err.println("R825SEED\t" + nameOf(mn) + "\t" + describe(o));
        Summ r = walk(mn, fr, seeds, -1, 0, true);
        if (r.why == null && r.lost != null && Candor.MASK_DEBUG)
            System.err.println("R825LOST\t" + nameOf(mn) + "\t" + r.lost);
        // A loaded handle that IS one of this body's parameters (a void loader on a caller's statement:
        // `addTo(st, sql) { st.addBatch(sql); }`) leaves through that parameter; the caller's argument holds it.
        Type[] ps = Type.getArgumentTypes(mn.desc);
        for (Object o : seeds)
            if (o instanceof Integer slot) {
                int p = paramIndexOfSlot(mn, slot);
                if (p >= 0 && p < ps.length) r.intoParams.set(p);
            }
        if (r.why != null) mark(mn, r.why);
        if (r.returns && returnedIntoLibraryDispatch(mn)) mark(mn, "returned-into-library-dispatch");
        if (r.returns && returnsTainted.add(mn)) {
            for (MethodNode c : callersByNameDesc.getOrDefault(mn.name + mn.desc, List.of())) enqueue(c);
            ClassNode cn = ownerOf.get(mn);
            if (cn != null) for (MethodNode c : indyUsersByImpl.getOrDefault(cn.name + "." + mn.name + mn.desc, List.of())) enqueue(c);
        }
        if (!r.intoParams.isEmpty()) {
            BitSet op = outParams.computeIfAbsent(mn, k -> new BitSet());
            BitSet before = (BitSet) op.clone();
            op.or(r.intoParams);
            if (!op.equals(before))
                for (MethodNode c : callersByNameDesc.getOrDefault(mn.name + mn.desc, List.of())) enqueue(c);
        }
    }

    /** Does some call site reach {@code mn} only through a LIBRARY supertype's declaration
     *  ({@code it.next()} on {@code java.util.Iterator}, where {@code mn} is a project iterator)? Those sites
     *  do not pick up the returned handle (above), so the handle is lost into code dispatching on a type this
     *  scan does not own — mark the implementor, fail CLOSED. */
    private boolean returnedIntoLibraryDispatch(MethodNode mn) {
        ClassNode cn = ownerOf.get(mn);
        if (cn == null || (mn.access & Opcodes.ACC_STATIC) != 0 || "<init>".equals(mn.name)) return false;
        Set<String> sup = Candor.transSupers(cn.name);
        for (String o : siteOwners.getOrDefault(mn.name + mn.desc, Set.of()))
            if (!ctx.projectClasses.contains(o) && sup.contains(o)) return true;
        return false;
    }

    private void mark(MethodNode mn, String why) {
        marked.putIfAbsent(mn, why);
    }

    private void taintField(String key) {
        if (taintedFields.add(key))
            for (MethodNode r : fieldReaders.getOrDefault(key, List.of())) enqueue(r);
    }

    // ── summaries: what a body does with a handle arriving in one slot ───────────────────────────────

    private Summ summary(MethodNode b, int slot, int depth) {
        Map<Integer, Summ> m = summaries.get(b);
        Summ have = m == null ? null : m.get(slot);
        if (have != null) return have;
        String key = System.identityHashCode(b) + ":" + slot;
        if (depth > MAX_DEPTH) {
            // Not provisional: a truncated summary is CACHED. Recomputing it at every shallower query made the
            // walk exponential once a lost handle stopped ending it (hibernate-core: 26 s → over 16 min).
            Summ s = new Summ();
            s.lost = "depth:" + nameOf(b);
            return s;
        }
        if (!inProgress.add(key)) { provisional = true; return new Summ(); }
        if (++work > WORK_BUDGET) throw new Budget();
        boolean outer = provisional;
        provisional = false;
        Summ s;
        try {
            Frame<SourceValue>[] fr = Candor.srcFramesOf(b);
            if (fr == null) {
                s = new Summ();
                s.lost = "no-frames:" + nameOf(b);
            } else s = walk(b, fr, Set.of(slot), slot, depth, false);
        } finally {
            inProgress.remove(key);
        }
        // Cached even when it consulted an in-progress summary (a recursion, answered optimistically). Leaving
        // such results uncached let a recursive visitor re-derive the same summaries exponentially. The error
        // this admits is a MISSED addition inside a recursion; the 0.39.2 floor is untouched by it.
        summaries.computeIfAbsent(b, k -> new HashMap<>()).put(slot, s);
        provisional |= outer;
        return s;
    }

    // ── the walk ─────────────────────────────────────────────────────────────────────────────────────

    /** Forward from {@code seeds} through one body. In a DEFINITE walk the seeds are handles this body
     *  obtained (so the body is marked on an execution or a loss); in a SUMMARY walk the seed is one
     *  parameter slot ({@code seedSlot}) and the answer is reported to the caller instead. */
    private Summ walk(MethodNode mn, Frame<SourceValue>[] fr, Set<Object> seeds, int seedSlot, int depth,
            boolean definite) {
        InsnList insns = mn.instructions;
        boolean inst = (mn.access & Opcodes.ACC_STATIC) == 0;
        Set<Object> tracked = new HashSet<>(seeds);
        Map<AbstractInsnNode, String> done = new HashMap<>();
        Summ res = new Summ();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (int j = 0; j < insns.size(); j++) {
                AbstractInsnNode ins = insns.get(j);
                Frame<SourceValue> f = fr[j];
                if (f == null) continue;
                int op = ins.getOpcode();
                int sz = f.getStackSize();
                if (op == Opcodes.AASTORE && sz >= 3) {
                    if (hit(fr, insns, tracked, f.getStack(sz - 1)))
                        changed |= absorb(mn, fr, insns, tracked, f.getStack(sz - 3), inst, seedSlot, res);
                } else if (op == Opcodes.AALOAD && sz >= 2) {
                    if (!tracked.contains(ins) && hit(fr, insns, tracked, f.getStack(sz - 2))) {
                        tracked.add(ins);
                        changed = true;
                    }
                } else if ((op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC) && sz >= 1) {
                    FieldInsnNode fi = (FieldInsnNode) ins;
                    if (!hit(fr, insns, tracked, f.getStack(sz - 1))) continue;
                    if (op == Opcodes.PUTFIELD && sz >= 2) {
                        // Into the object: `this.q = q` in a constructor makes the object a holder.
                        changed |= absorb(mn, fr, insns, tracked, f.getStack(sz - 2), inst, seedSlot, res);
                    }
                    // A PROJECT field (or any static) is shared storage: every read of it anywhere is tainted.
                    // A library class's instance field (`Ref$ObjectRef.element`) is tracked through its
                    // object instead, or every Kotlin captured local in the program would share one taint.
                    // …but only a field whose TYPE can hold a handle is keyed globally. An `Object`-typed or
                    // arbitrary-typed field (a generic `Box<T>.v`, `BiTuple.element1`) is tracked through its
                    // object alone: keyed globally, one runtime handle in one Box tainted every Box read in the
                    // program (measured: `BiTuple.element1`, `Invocation.op` seeding thousands of hazelcast
                    // bodies, and the literal `k4LitBox` fixture marked). A handle stored that way into `this`
                    // cannot be followed to another method, so a DEFINITE walk marks there (fail CLOSED).
                    Type pft = Type.getType(fi.desc);
                    if ((op == Opcodes.PUTSTATIC && (handleCapable(pft) || pft.getDescriptor().equals("Ljava/lang/Object;")))
                            || (ctx.projectClasses.contains(fi.owner) && handleCapable(pft)))
                        taintField(fkey(fi));
                    else if (op == Opcodes.PUTFIELD && definite && inst && sz >= 2
                            && roots(fr, insns, f.getStack(sz - 2)).contains(0)) {
                        if (res.lost == null) res.lost = "stored-into-this:" + fi.owner + "." + fi.name;
                    }
                } else if ((op == Opcodes.GETFIELD || op == Opcodes.GETSTATIC) && !tracked.contains(ins)) {
                    FieldInsnNode fi = (FieldInsnNode) ins;
                    if (!holder(Type.getType(fi.desc))) continue;
                    boolean t = definite && taintedFields.contains(fkey(fi));
                    // Read THROUGH a tracked object: only a field that can itself be the handle (a handle type,
                    // a container, or an erased `Object` — the `Box<T>.v` case). A statement proxy's
                    // `connection` field is not the statement it wraps.
                    Type ft = Type.getType(fi.desc);
                    if (!t && op == Opcodes.GETFIELD && sz >= 1
                            && (handleCapable(ft) || (ft.getSort() == Type.OBJECT && ft.getInternalName().equals("java/lang/Object"))))
                        t = hit(fr, insns, tracked, f.getStack(sz - 1));
                    if (t) { tracked.add(ins); changed = true; }
                } else if (op == Opcodes.ARETURN && sz >= 1) {
                    if (hit(fr, insns, tracked, f.getStack(sz - 1))) res.returns = true;
                } else if (ins instanceof InvokeDynamicInsnNode idin) {
                    String why = indy(mn, fr, insns, f, idin, tracked, depth, done);
                    if (why != null) { if (seenExec(why)) { res.why = why; return res; } if (res.lost == null) res.lost = why; }
                    if (tracked.contains(idin) && !done.containsKey(idin)) { done.put(idin, ""); changed = true; }
                } else if (ins instanceof MethodInsnNode m) {
                    int before = tracked.size();
                    String why = call(mn, fr, insns, f, m, tracked, depth, inst, seedSlot, res, done);
                    if (why != null) { if (seenExec(why)) { res.why = why; return res; } if (res.lost == null) res.lost = why; }
                    if (tracked.size() != before) changed = true;
                }
            }
        }
        return res;
    }

    private boolean hit(Frame<SourceValue>[] fr, InsnList insns, Set<Object> tracked, SourceValue v) {
        for (Object r : roots(fr, insns, v)) if (tracked.contains(r)) return true;
        return false;
    }

    /** The handle went INTO {@code container}: track the container's producers. A container that is a
     *  project field (or a static) taints the field; `this` and another parameter are reported upward. */
    private boolean absorb(MethodNode mn, Frame<SourceValue>[] fr, InsnList insns, Set<Object> tracked, SourceValue container,
            boolean inst, int seedSlot, Summ res) {
        boolean changed = false;
        for (Object r : roots(fr, insns, container)) {
            if (r instanceof Integer slot) {
                if (inst && slot == 0) { res.intoRecv = true; continue; }
                if (slot != seedSlot) {
                    int p = paramIndexOfSlot(mn, slot);
                    if (p >= 0) res.intoParams.set(p);
                }
            }
            if (r instanceof FieldInsnNode gf && handleCapable(Type.getType(gf.desc))
                    && (gf.getOpcode() == Opcodes.GETSTATIC || ctx.projectClasses.contains(gf.owner)))
                taintField(fkey(gf));
            if (tracked.add(r)) changed = true;
        }
        return changed;
    }

    /** SOUNDNESS R825 — one call with a tracked operand. Returns a reason to MARK, or null. */
    private String call(MethodNode mn, Frame<SourceValue>[] fr, InsnList insns, Frame<SourceValue> f,
            MethodInsnNode m, Set<Object> tracked, int depth, boolean inst, int seedSlot, Summ res,
            Map<AbstractInsnNode, String> done) {
        Type[] args = Type.getArgumentTypes(m.desc);
        boolean isStatic = m.getOpcode() == Opcodes.INVOKESTATIC;
        int base = f.getStackSize() - args.length - (isStatic ? 0 : 1);
        if (base < 0) return null;
        boolean hitRecv = !isStatic && hit(fr, insns, tracked, f.getStack(base));
        BitSet hitArgs = new BitSet();
        int off = isStatic ? 0 : 1;
        for (int k = 0; k < args.length; k++)
            if (hit(fr, insns, tracked, f.getStack(base + off + k))) hitArgs.set(k);
        if (!hitRecv && hitArgs.isEmpty()) return null;
        String sig = (hitRecv ? "R" : "") + hitArgs;
        if (sig.equals(done.get(m))) return null;
        done.put(m, sig);
        String where = m.owner + "." + m.name;
        Type ret = Type.getReturnType(m.desc);

        // (1) A Db call with a handle in any position RUNS it.
        if (Classifier.classify(m.owner.replace('/', '.'), m.name, m.desc) == Effect.DB) return "exec:" + where;

        // (2) Project code: ask each body what it does with the handle in that slot.
        // Through a runtime DATA-STRUCTURE declaration (`map.get(k)`, `o.equals(x)`, `list.add(q)`) CHA would
        // fan out to every project class implementing Map or overriding equals; the carrier rule below already
        // says what such a call does with a handle. A project Map whose `put` RUNS a query is the one shape
        // this forgets — named, SILENT.
        List<MethodNode> bodies = !ctx.projectClasses.contains(m.owner) && isCarrier(m.owner) ? List.of() : bodiesOf(m);
        // `dbProjectBodies` stops at 17: past that the implementor that runs the handle may be the one cut off.
        if (bodies.size() > 16) return "cha-cap:" + where;
        if (!bodies.isEmpty()) {
            for (MethodNode b : bodies) {
                if (((b.access & Opcodes.ACC_STATIC) != 0) != isStatic) continue;
                List<int[]> slots = new ArrayList<>();   // {slot, argIndex or -1}
                if (hitRecv) slots.add(new int[]{0, -1});
                for (int k = hitArgs.nextSetBit(0); k >= 0; k = hitArgs.nextSetBit(k + 1))
                    slots.add(new int[]{slotOf(args, isStatic, k), k});
                for (int[] sl : slots) {
                    Summ s = summary(b, sl[0], depth + 1);
                    if (s.why != null) return "param-of:" + where + ">" + s.why;
                    if (s.returns && holder(ret)) tracked.add(m);
                    if (s.intoRecv && !isStatic) absorb(mn, fr, insns, tracked, f.getStack(base), inst, seedSlot, res);
                    for (int p = s.intoParams.nextSetBit(0); p >= 0; p = s.intoParams.nextSetBit(p + 1))
                        if (p < args.length) absorb(mn, fr, insns, tracked, f.getStack(base + off + p), inst, seedSlot, res);
                }
            }
            return null;
        }
        // A project owner with no concrete body anywhere in the scan (an interface nobody here implements):
        // the code that receives the handle is not visible. Fail CLOSED.
        // (An API interface compiled INTO the scan — `jakarta.persistence.Query` in a fat jar — is still the
        // library type it names: the SQL-bearing and carrier rules below apply to it.)
        if (ctx.projectClasses.contains(m.owner) && !Candor.isSqlBearingOwner(m.owner) && !isCarrier(m.owner))
            return "no-body:" + where;

        // (3) Library code from here on.
        // (3a) A callback handed to the same call as the handle: the library will apply it to the handle.
        for (int k = 0; k < args.length; k++) {
            if (hitArgs.get(k)) continue;
            SourceValue av = f.getStack(base + off + k);
            boolean sawIndy = false;
            for (Object r : roots(fr, insns, av)) {
                if (!(r instanceof InvokeDynamicInsnNode idin)) continue;
                sawIndy = true;
                Handle h = implHandle(idin);
                if (h == null) continue;
                if (Classifier.classify(h.getOwner().replace('/', '.'), h.getName(), h.getDesc()) == Effect.DB)
                    return "callback-exec:" + h.getOwner() + "." + h.getName() + " via " + where;
                MethodNode b = projectBody(h.getOwner(), h.getName(), h.getDesc());
                if (b == null) continue;   // a library method reference (`Object::toString`): a value, not a runner
                int captured = Type.getArgumentTypes(idin.desc).length;
                Type[] bp = Type.getArgumentTypes(b.desc);
                boolean bStatic = (b.access & Opcodes.ACC_STATIC) != 0;
                int nonCapturedFrom = h.getTag() == Opcodes.H_INVOKESTATIC ? captured : Math.max(0, captured - 1);
                if (h.getTag() != Opcodes.H_INVOKESTATIC && captured == 0) {
                    // An UNBOUND instance method ref (`Q::run`): the element arrives as the receiver.
                    Summ s = summary(b, 0, depth + 1);
                    if (s.why != null) return "callback:" + where + ">" + s.why;
                    if (s.returns && holder(ret)) tracked.add(m);
                }
                for (int p = nonCapturedFrom; p < bp.length; p++) {
                    int slot = (bStatic ? 0 : 1);
                    for (int q = 0; q < p; q++) slot += bp[q].getSize();
                    Summ s = summary(b, slot, depth + 1);
                    if (s.why != null) return "callback:" + where + ">" + s.why;
                    if (s.returns && holder(ret)) tracked.add(m);
                }
            }
            // A function value we did not see created, handed to the same library call as the handle.
            if (!sawIndy && isFunctionalType(args[k])) return "opaque-callback:" + where;
        }
        // (3b) Invoking a function value WITH the handle as an argument: its body is whatever lambda or
        // implementor reached it. Visible project ones are asked; none visible is opaque — fail CLOSED.
        if (!hitArgs.isEmpty() && isFunctionalOwner(m.owner, m.name, m.desc)) {
            List<MethodNode> impls = new ArrayList<>();
            for (String id : Cha.samLambdaImplementors(m.owner, m.name, m.desc)) {
                MethodNode b = byId.get(id);
                if (b != null) impls.add(b);
            }
            if (impls.isEmpty()) return "opaque-callback:" + where;
            for (MethodNode b : impls) {
                Type[] bp = Type.getArgumentTypes(b.desc);
                boolean bStatic = (b.access & Opcodes.ACC_STATIC) != 0;
                int lead = bp.length - args.length;   // captured values precede the SAM's own arguments
                for (int k = hitArgs.nextSetBit(0); k >= 0; k = hitArgs.nextSetBit(k + 1)) {
                    int slot;
                    if (lead < 0) { if (!bStatic && k == 0) slot = 0; else continue; }
                    else {
                        slot = bStatic ? 0 : 1;
                        for (int q = 0; q < lead + k; q++) slot += bp[q].getSize();
                    }
                    Summ s = summary(b, slot, depth + 1);
                    if (s.why != null) return "lambda-of:" + where + ">" + s.why;
                    if (s.returns && holder(ret)) tracked.add(m);
                }
            }
            return null;
        }
        if (isFunctionalOwner(m.owner, m.name, m.desc)) {   // a function value that HOLDS the handle, applied
            if (holder(ret)) tracked.add(m);
            return null;
        }
        // (3c) A SQL-bearing owner that is not Db: a builder step on the handle (`setParameter`,
        // `setMaxResults`, `unwrap`) returns it; a handle handed to one (`createQuery(criteria)`) yields one.
        // Not absorbed into the receiver: a session or statement is the factory of queries, not their store.
        if (Candor.isSqlBearingOwner(m.owner)) {
            // (`unwrap(Class)` erases to Object, and Object is a holder: only the FACTORY types are cut.)
            if (holder(ret) && !(ret.getSort() == Type.OBJECT && NON_HANDLE.contains(ret.getInternalName())
                    && !ret.getInternalName().equals("java/lang/Object")))
                tracked.add(m);
            return null;
        }
        // (3d) A log sink: formats the value and keeps nothing a caller can get back.
        if (isLogSink(m.owner)) return null;
        if (isReflectiveRunner(m.owner, m.name)) return "reflective:" + where;
        // (3e) A DATA STRUCTURE the runtime ships: it stores the handle and gives it back only through its
        // receiver or its result, never runs it. The handle is absorbed into the receiver (an instance call
        // handed the handle) or into every other object argument (a static one — `Collections.addAll(l, q)`),
        // and the result carries it.
        if (isCarrier(m.owner)) {
            if (holder(ret)) tracked.add(m);
            if (!isStatic && !hitArgs.isEmpty()) absorb(mn, fr, insns, tracked, f.getStack(base), inst, seedSlot, res);
            // A STATIC one only: an instance container keeps the handle in ITSELF, and absorbing into its
            // other arguments made the KEY of `m.put(sql, q)` a handle — and with it the `sql` that loaded q.
            if (isStatic)
                for (int k = 0; k < args.length; k++)
                    // Only an argument that can HOLD the handle absorbs it (`Collections.addAll(list, q)`,
                    // `System.arraycopy(src, 0, dst, 0, n)`) — not `Locale.ROOT` in `String.format(Locale.ROOT,
                    // fmt, q)`, which as a static root tainted 966 hibernate reads of `Locale.ROOT`.
                    if (!hitArgs.get(k) && (handleCapable(args[k])
                            || (args[k].getSort() == Type.OBJECT && args[k].getInternalName().equals("java/lang/Object"))))
                        absorb(mn, fr, insns, tracked, f.getStack(base + off + k), inst, seedSlot, res);
            return null;
        }
        // (3f) Anything else is library code this scan cannot see into, holding a runtime query handle.
        return "lib:" + where;
    }

    /** An invokedynamic whose captured operands include a tracked handle — a lambda capture or a BOUND
     *  method reference. The function value holds the handle from here on; if its body (or the method it
     *  names) runs the handle, it runs it when applied, so the capturing frame is marked. */
    private String indy(MethodNode mn, Frame<SourceValue>[] fr, InsnList insns, Frame<SourceValue> f,
            InvokeDynamicInsnNode idin, Set<Object> tracked, int depth, Map<AbstractInsnNode, String> done) {
        Type[] caps = Type.getArgumentTypes(idin.desc);
        int base = f.getStackSize() - caps.length;
        if (base < 0 || caps.length == 0) return null;
        BitSet hitCaps = new BitSet();
        for (int k = 0; k < caps.length; k++) if (hit(fr, insns, tracked, f.getStack(base + k))) hitCaps.set(k);
        if (hitCaps.isEmpty()) return null;
        String bsm = idin.bsm == null ? "" : idin.bsm.getOwner();
        if (bsm.equals("java/lang/invoke/StringConcatFactory") || bsm.equals("java/lang/runtime/ObjectMethods")
                || bsm.equals("java/lang/runtime/SwitchBootstraps")) return null;
        Handle h = implHandle(idin);
        if (h == null) return "indy:" + bsm + "." + idin.name;   // a dynamic call site (Groovy, JRuby): opaque
        String where = h.getOwner() + "." + h.getName();
        if (Classifier.classify(h.getOwner().replace('/', '.'), h.getName(), h.getDesc()) == Effect.DB)
            return "bound-exec:" + where;
        MethodNode b = projectBody(h.getOwner(), h.getName(), h.getDesc());
        if (b != null) {
            Type[] bp = Type.getArgumentTypes(b.desc);
            boolean bStatic = (b.access & Opcodes.ACC_STATIC) != 0;
            for (int k = hitCaps.nextSetBit(0); k >= 0; k = hitCaps.nextSetBit(k + 1)) {
                int slot;
                if (bStatic) {
                    slot = 0;
                    for (int q = 0; q < k && q < bp.length; q++) slot += bp[q].getSize();
                } else if (h.getTag() == Opcodes.H_NEWINVOKESPECIAL) {
                    slot = 1;
                    for (int q = 0; q < k && q < bp.length; q++) slot += bp[q].getSize();
                } else if (k == 0) slot = 0;
                else {
                    slot = 1;
                    for (int q = 0; q < k - 1 && q < bp.length; q++) slot += bp[q].getSize();
                }
                Summ s = summary(b, slot, depth + 1);
                if (s.why != null) return "captured-by:" + where + ">" + s.why;
            }
        }
        tracked.add(idin);
        return null;
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────────

    private List<MethodNode> bodiesOf(MethodInsnNode m) {
        if ("<init>".equals(m.name)) {
            MethodNode b = projectBody(m.owner, m.name, m.desc);
            return b == null ? List.of() : List.of(b);
        }
        List<MethodNode> out = Candor.dbProjectBodies(ctx, m);
        if (out.isEmpty() || !out.contains(inheritedBody(m.owner, m.name, m.desc))) {
            // An INHERITED body: the instruction names the class it was called through, and the declaration
            // lives on a project superclass (`HikariPool.quietlyCloseConnection` is declared on `PoolBase`).
            MethodNode inh = inheritedBody(m.owner, m.name, m.desc);
            if (inh != null && !out.contains(inh)) {
                out = new ArrayList<>(out);
                out.add(inh);
            }
        }
        return out;
    }

    /** The concrete project declaration a call on {@code owner} resolves to up the superclass chain. */
    private MethodNode inheritedBody(String owner, String name, String desc) {
        for (String t = owner; t != null; ) {
            ClassNode cn = ctx.byName.get(t);
            if (cn == null) return null;
            MethodNode b = Candor.findMethod(cn, name, desc);
            if (b != null) return (b.access & Opcodes.ACC_ABSTRACT) == 0 && b.instructions != null
                    && b.instructions.size() > 0 ? b : null;
            t = cn.superName;
        }
        return null;
    }

    private MethodNode projectBody(String owner, String name, String desc) {
        ClassNode cn = ctx.byName.get(owner);
        MethodNode b = cn == null ? null : Candor.findMethod(cn, name, desc);
        return b != null && (b.access & Opcodes.ACC_ABSTRACT) == 0 && b.instructions != null
                && b.instructions.size() > 0 ? b : null;
    }

    static Handle implHandle(InvokeDynamicInsnNode idin) {
        if (idin.bsm == null) return null;
        String o = idin.bsm.getOwner();
        if (!o.equals("java/lang/invoke/LambdaMetafactory")) return null;
        for (Object a : idin.bsmArgs) if (a instanceof Handle h) return h;
        return null;
    }

    private String fkey(FieldInsnNode fi) {
        return Cha.fieldKey(fi.owner, fi.name);
    }

    /** {@link Candor#dbRoots}, plus the stack SHUFFLES it treats as producers: Kotlin's inlined collection
     *  builders emit `aload dst; swap; invokeinterface add`, so the receiver of `add` is a SWAP, and a walk
     *  that stops there never reaches the list it filled. A shuffle cannot say which input each output came
     *  from, so its roots are the UNION of the shuffled inputs — an over-approximation, which can only carry
     *  taint further. */
    private static Set<Object> roots(Frame<SourceValue>[] fr, InsnList insns, SourceValue v) {
        Set<Object> out = new LinkedHashSet<>();
        Deque<SourceValue> work = new ArrayDeque<>();
        work.add(v);
        Set<AbstractInsnNode> seen = new HashSet<>();
        while (!work.isEmpty()) {
            SourceValue cur = work.poll();
            SourceValue plain = new SourceValue(cur.size, new HashSet<>());
            for (AbstractInsnNode p : cur.insns) {
                int op = p.getOpcode();
                int n = switch (op) {
                    case Opcodes.SWAP, Opcodes.DUP_X1, Opcodes.DUP2 -> 2;
                    case Opcodes.DUP_X2, Opcodes.DUP2_X1 -> 3;
                    case Opcodes.DUP2_X2 -> 4;
                    default -> 0;
                };
                if (n == 0) { plain.insns.add(p); continue; }
                if (!seen.add(p)) continue;
                int i = insns.indexOf(p);
                Frame<SourceValue> f = i >= 0 ? fr[i] : null;
                if (f == null) { out.add(p); continue; }
                for (int k = Math.max(0, f.getStackSize() - n); k < f.getStackSize(); k++) work.add(f.getStack(k));
            }
            if (plain.insns.isEmpty()) continue;
            for (Object r : Candor.dbRoots(fr, insns, plain)) {
                // dbRoots looks through locals, so a shuffle can surface again BEHIND a store.
                if (r instanceof AbstractInsnNode p && isShuffle(p.getOpcode()) && !seen.contains(p))
                    work.add(new SourceValue(1, Set.of(p)));
                else out.add(r);
            }
        }
        return out;
    }

    /** A declared type a query handle can live in: a query/statement type, a type some Db call runs, a
     *  runtime container, a function value, or an object array. NOT {@code Object} and not an arbitrary
     *  class — see the field rule in {@link #walk}. */
    private boolean handleCapable(Type t) {
        // An array only when its ELEMENT type is capable: an `Object[]` field is every generic array store in
        // the program (hibernate's `Stack.elements` seeded 1,472 `pop()` sites).
        if (t.getSort() == Type.ARRAY) return t.getDimensions() == 1 && handleCapable(t.getElementType());
        if (t.getSort() != Type.OBJECT) return false;
        String n = t.getInternalName();
        if (NON_HANDLE.contains(n)) return false;
        return sourceTypes.contains(n) || n.equals("java/sql/Statement") || n.equals("java/sql/PreparedStatement")
                || n.equals("java/sql/CallableStatement") || isRuntimeContainer(n) || isFunctionalName(n) || n.startsWith("kotlin/collections/") || n.startsWith("scala/collection/")
                || n.equals("java/lang/ThreadLocal") || n.equals("java/lang/Iterable");
    }

    /** A runtime CONTAINER type — a thing that stores objects — as opposed to the rest of {@code java.util}
     *  ({@code Locale}, {@code UUID}, {@code Date}, {@code regex.Pattern}), which cannot hold a handle. */
    static boolean isRuntimeContainer(String n) {
        if (!(n.startsWith("java/util/"))) return false;
        String leaf = n.substring(n.lastIndexOf('/') + 1);
        int d = leaf.lastIndexOf('$');
        if (d >= 0) leaf = leaf.substring(d + 1);
        return leaf.endsWith("List") || leaf.endsWith("Set") || leaf.endsWith("Map") || leaf.endsWith("Queue")
                || leaf.endsWith("Deque") || leaf.endsWith("Collection") || leaf.endsWith("Iterator")
                || leaf.endsWith("Iterable") || leaf.startsWith("Optional") || leaf.equals("Stack")
                || leaf.equals("Vector") || leaf.equals("Hashtable") || leaf.equals("Enumeration")
                || leaf.equals("Entry") || leaf.startsWith("AtomicReference") || leaf.equals("Stream")
                || leaf.equals("Spliterator");
    }

    private static boolean isShuffle(int op) {
        return op == Opcodes.SWAP || op == Opcodes.DUP_X1 || op == Opcodes.DUP_X2 || op == Opcodes.DUP2
                || op == Opcodes.DUP2_X1 || op == Opcodes.DUP2_X2;
    }

    static boolean holder(Type t) {
        if (t.getSort() == Type.ARRAY) return t.getElementType().getSort() == Type.OBJECT;
        if (t.getSort() != Type.OBJECT) return false;
        String n = t.getInternalName();
        return !NON_HOLDER.contains(n) && (n.equals("java/lang/Object") || !NON_HANDLE.contains(n));
    }

    private static int slotOf(Type[] args, boolean isStatic, int k) {
        int slot = isStatic ? 0 : 1;
        for (int q = 0; q < k; q++) slot += args[q].getSize();
        return slot;
    }

    private static SourceValue receiverOf(Frame<SourceValue> f, MethodInsnNode m) {
        if (m.getOpcode() == Opcodes.INVOKESTATIC) return null;
        int ri = f.getStackSize() - Type.getArgumentTypes(m.desc).length - 1;
        return ri < 0 ? null : f.getStack(ri);
    }

    private static SourceValue operand(Frame<SourceValue> f, MethodInsnNode m, int argIndex) {
        Type[] args = Type.getArgumentTypes(m.desc);
        int i = f.getStackSize() - args.length + argIndex;
        return i < 0 || argIndex >= args.length ? null : f.getStack(i);
    }

    /** Which declared parameter of {@code mn} local slot {@code slot} is, or -1 (`this`, or not a parameter). */
    private static int paramIndexOfSlot(MethodNode mn, int slot) {
        int at = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        Type[] ps = Type.getArgumentTypes(mn.desc);
        for (int p = 0; p < ps.length; p++) {
            if (at == slot) return p;
            at += ps[p].getSize();
        }
        return -1;
    }

    /** A functional interface: calling it runs code chosen elsewhere. A DENYLIST from the point of view of
     *  the carrier rule below: a functional owner is never a carrier. */
    static boolean isFunctionalOwner(String owner, String name, String desc) {
        return isFunctionalName(owner) || !Cha.samLambdaImplementors(owner, name, desc).isEmpty();
    }

    static boolean isFunctionalType(Type t) {
        return t.getSort() == Type.OBJECT && isFunctionalName(t.getInternalName());
    }

    private static boolean isFunctionalName(String o) {
        return o.startsWith("java/util/function/") || o.equals("java/lang/Runnable")
                || o.equals("java/util/concurrent/Callable") || o.equals("java/util/Comparator")
                || o.startsWith("kotlin/jvm/functions/") || o.startsWith("scala/Function")
                || o.startsWith("groovy/lang/Closure");
    }

    /** The runtime's own data structures and value utilities: they store a handle and hand it back only
     *  through their receiver or their result. EVERY OTHER library owner falls to (3f) and MARKS, so an
     *  owner missing from here over-marks. Reflection, {@code java.lang.invoke} and the functional
     *  interfaces are excluded explicitly — they run code with their operands. */
    static boolean isCarrier(String o) {
        if (o.startsWith("java/lang/invoke/") || isFunctionalName(o)) return false;
        // Reflection RUNS or STORES through `Method.invoke`, `Constructor.newInstance`, `Field.set` — see
        // {@link #isReflectiveRunner}; every other `java.lang.reflect` call only describes a type.
        if (o.startsWith("java/lang/reflect/")) return true;
        if (NON_HOLDER.contains(o) || o.equals("java/lang/Number")) return true;   // a value's own methods
        return o.startsWith("java/util/") || o.equals("java/lang/Object") || o.equals("java/lang/Iterable")
                || o.equals("java/lang/String") || o.equals("java/lang/StringBuilder")
                || o.equals("java/lang/StringBuffer") || o.equals("java/lang/Class") || o.equals("java/lang/System")
                || o.equals("java/lang/ThreadLocal") || o.equals("java/lang/InheritableThreadLocal")
                || o.startsWith("java/lang/ref/") || o.equals("java/lang/Enum") || o.equals("java/lang/Record")
                || o.startsWith("kotlin/collections/") || o.equals("kotlin/jvm/internal/Intrinsics")
                || o.startsWith("kotlin/jvm/internal/Ref") || o.equals("kotlin/Pair") || o.equals("kotlin/Triple")
                || o.equals("kotlin/Result") || o.startsWith("kotlin/sequences/")
                || o.startsWith("scala/collection/") || o.equals("scala/Option") || o.equals("scala/Some")
                || o.startsWith("scala/Tuple") || o.startsWith("scala/runtime/ObjectRef")
                // Argument VALIDATORS: inspect the value and return it (`checkNotNull(q)`) or nothing. A
                // carrier, not a sink, so the returned handle is still followed.
                || o.equals("org/springframework/util/Assert") || o.equals("com/google/common/base/Preconditions")
                || o.equals("com/google/common/base/Verify") || o.equals("org/apache/commons/lang3/Validate")
                || o.equals("org/apache/commons/lang/Validate")
                // Value utilities and holders the corpus A/B found handed a handle (spring-data-cassandra):
                // null-safe equals/hash, a lazy holder, a reactor context lookup.
                || o.equals("org/springframework/util/ObjectUtils") || o.equals("java/util/Objects")
                || o.equals("org/springframework/data/util/Lazy") || o.startsWith("reactor/util/context/Context");
    }

    static boolean isReflectiveRunner(String o, String n) {
        return (o.equals("java/lang/reflect/Method") && n.equals("invoke"))
                || (o.equals("java/lang/reflect/Constructor") && n.equals("newInstance"))
                || (o.equals("java/lang/reflect/Field") && n.startsWith("set"));
    }

    /** Loggers and {@code java.io} writers: format or serialize the value, keep nothing a caller reads back
     *  as the same object. */
    static boolean isLogSink(String o) {
        return o.startsWith("java/io/") || o.startsWith("org/slf4j/") || o.startsWith("org/apache/logging/log4j/")
                || o.startsWith("org/apache/commons/logging/") || o.startsWith("org/apache/log4j/")
                || o.startsWith("org/jboss/logging/") || o.startsWith("ch/qos/logback/")
                || o.startsWith("java/lang/System$Logger") || o.startsWith("mu/KLogger")
                || o.startsWith("io/github/oshai/kotlinlogging/");
    }
}
