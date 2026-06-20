package io.poly.candor;

import java.util.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;

/** Literal extraction for the gate surface — host/cmd/path/table/url constants pulled from bytecode
 *  (the Net/Exec/Fs/Db endpoint literals candor surfaces + the masking/coverage checks). EXTRACTED
 *  from Candor.java (refactor P3); reaches Candor state (hostsDirect etc.) + helpers via the static
 *  import. See REFACTOR_PLAN.md. */
final class Literals {
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
    static int countChar(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    static String hostPart(String h) {
        // Byte-for-byte the candor-rust `policy::host_part` (the GATE-side normalizer): strip ONLY a
        // `[ipv6]` bracket or a trailing `:port`. It does NOT strip scheme/path/userinfo — an earlier
        // java-only version did, which (a) diverged from rust (same policy → different verdict across
        // engines) and (b) silently WIDENED a policy author's allow literal: `allow Net build@github.com`
        // got cleaned to `github.com`, broadening the intended scope. The REACHED host stored in
        // hostsDirect is already a clean authority (netHostLiteral drops scheme/path/userinfo at
        // extraction), so the gate compares clean-vs-clean; the allow literal is taken verbatim, as rust
        // does. A bracketed `[ipv6]`/`[ipv6]:port` → the bracketed host; a BARE IPv6 (>1 colon, no
        // brackets) → returned whole (a naive first-colon split collapsed every `2001:db8::*` to `2001`,
        // so one allowed IPv6 accepted the whole block); host/IPv4 (≤1 colon) → split at the colon.
        if (h.startsWith("[")) {
            int close = h.indexOf(']');
            return close >= 0 ? h.substring(1, close) : h.substring(1);
        }
        if (countChar(h, ':') > 1) return h;   // bare IPv6 literal — no port suffix to strip
        int colon = h.indexOf(':');
        return colon >= 0 ? h.substring(0, colon) : h;
    }

    /** Propagate a literal-detail map (hosts / commands / paths) along the SAME call graph as effects, so
     *  a method that reaches the effect only through a callee still sees the callee's literals — the scale
     *  path for AS-EFF-008 (the literal often lives in a deep, even cross-layer, callee). */
    static Map<String, TreeSet<String>> literalFixpoint(Map<String, TreeSet<String>> direct) {
        Map<String, TreeSet<String>> acc = new HashMap<>();
        for (var e : direct.entrySet()) acc.put(e.getKey(), new TreeSet<>(e.getValue()));
        boolean changed = true;
        while (changed) {
            changed = false;
            for (var caller : ctx().edges.keySet()) {
                TreeSet<String> add = new TreeSet<>();
                for (String c : ctx().edges.get(caller)) {
                    var ce = acc.get(c);
                    if (ce != null) add.addAll(ce);
                }
                if (add.isEmpty()) continue;
                var set = acc.computeIfAbsent(caller, k -> new TreeSet<>());
                int before = set.size();
                set.addAll(add);
                if (set.size() != before) changed = true;
            }
        }
        return acc;
    }

    /** The literal command/path a targeted call carries: the FIRST string constant pushed for its
     *  arguments (the program for `new ProcessBuilder("git","clone")` → `git`, element 0 of the varargs
     *  array; the path for `Path.of("/etc/app")`). Scans BACK from the call collecting `String` LDCs until
     *  a prior method call / jump bounds the argument block, then returns the EARLIEST — the first arg, not
     *  a trailing flag / the data of `Files.write(path, "content")`. Null if no literal. Never over-claims
     *  (SPEC §2): under-extracts a runtime-computed value rather than guessing. */
    static String firstLiteralArg(MethodNode mn, AbstractInsnNode call) {
        String found = null;
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            // Bound the back-scan at the START of THIS call's statement, so a literal from a PRIOR
            // statement is never grabbed. Without the NEW/store bounds, `new Socket(runtimeHost, 443)`
            // preceded by `String tag = "internal.metrics.svc"` captured `tag` as the host — fabricating a
            // host on a runtime-computed destination and DEFEATING the AS-EFF-008 allowlist (an attacker
            // host certified under the wrong literal). Boundaries: a prior call/branch (already), the
            // receiver's `new` (a constructor's allocation begins this statement; a real literal ARG sits
            // after the NEW/DUP so it's still captured), and a `*STORE`/PUTFIELD/PUTSTATIC ending the prior
            // statement.
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode
                    || (n instanceof TypeInsnNode && n.getOpcode() == Opcodes.NEW)
                    || (n instanceof VarInsnNode v && v.getOpcode() >= Opcodes.ISTORE
                            && v.getOpcode() <= Opcodes.ASTORE)
                    || (n instanceof FieldInsnNode fi
                            && (fi.getOpcode() == Opcodes.PUTFIELD || fi.getOpcode() == Opcodes.PUTSTATIC)))
                break;
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) found = s; // keep the earliest
        }
        return found;
    }

    /** The internal owners whose `<init>` (or `URI.create`) builds a URL/URI VALUE — the host-establishing
     *  CONSTRUCTION of the split construct-then-use idiom (`new URL(host).openStream()`). Distinct from the
     *  Net TERMINAL (openStream/openConnection/getContent), which carries no host arg of its own. */
    static boolean isUrlValueOwner(String internalOwner) {
        return internalOwner.equals("java/net/URL") || internalOwner.equals("java/net/URI");
    }

    /** The host literal attributable to a URL/URI Net TERMINAL's receiver, or null when no literal host is
     *  cheaply attributable (then the gate must fail-CLOSED — see surfaceIncomplete). The Net effect of
     *  `URL.openStream()`/`openConnection()`/`getContent()` fires on the terminal, but the host is fixed at
     *  the `new URL(String)` CONSTRUCTION, which is NOT itself a Net call. Without linking the two, a benign
     *  `new URL("good.com").openStream()` populated the method's host surface and MASKED a sibling
     *  `new URL(getenv).openStream()` — the AS-EFF-008 URL split construct/use gate EVASION. Two shapes are
     *  cheaply attributable (anything else → null = incomplete, the sound over-approximation):
     *   (1) INLINE — `new URL("lit").openStream()`: the receiver is constructed by the INVOKESPECIAL
     *       `URL.<init>` (or `URI.create`/`URI.<init>`) immediately preceding the terminal in this statement;
     *       read that ctor's first literal arg.
     *   (2) THROUGH A CONST LOCAL — `URL u = new URL("lit"); u.openStream()`: the receiver is an ALOAD of a
     *       local whose EVERY definition is a `new URL(lit)`/`URI.create(lit)` (urlLocals, built like
     *       constStringLocals) — so resolving its host is sound. */
    static String urlTerminalHost(AbstractInsnNode terminal, Map<Integer, String> urlLocals,
            Map<Integer, String> constLocals) {
        // The instruction producing the receiver sits immediately before the terminal (the terminal takes
        // no args). Skip pseudo-insns (labels/line-numbers/frames, opcode < 0).
        AbstractInsnNode r = terminal.getPrevious();
        while (r != null && r.getOpcode() < 0) r = r.getPrevious();
        if (r == null) return null;
        // (1) INLINE: receiver is the URL/URI value-building call (`new URL("lit")` → INVOKESPECIAL <init>;
        //     `URI.create("lit")` → INVOKESTATIC). Extract the host from ITS own argument window.
        if (r instanceof MethodInsnNode ctor && isUrlValueOwner(ctor.owner)
                && (ctor.name.equals("<init>") || ctor.name.equals("create"))) {
            for (String lit : literalArgsInWindow(ctor, constLocals)) {
                String hl = netHostLiteral(lit);
                if (hl != null) return hl;
            }
            return null; // a URL built from a RUNTIME string — no literal host attributable
        }
        // (2) THROUGH A LOCAL: `u.openStream()` where the receiver is an ALOAD of a const-URL local.
        if (r instanceof VarInsnNode v && v.getOpcode() == Opcodes.ALOAD && urlLocals.containsKey(v.var))
            return urlLocals.get(v.var);
        return null;
    }

    /** Locals provably bound to a single `new URL(lit)`/`URI.create(lit)` whose host literal is statically
     *  known — the two-statement split `URL u = new URL("https://good.com"); u.openStream();`. An index ever
     *  stored a runtime URL, two different literal hosts, or a non-URL value is ambiguous and EXCLUDED, so a
     *  later `u.openStream()` reads incomplete (fail-closed) rather than inheriting a benign host. Mirrors
     *  {@link #constStringLocals} but keys on the URL-value ctor and stores the EXTRACTED host. */
    static Map<Integer, String> constUrlLocals(MethodNode mn, Map<Integer, String> constLocals) {
        Map<Integer, String> m = new HashMap<>();
        Set<Integer> ambiguous = new HashSet<>();
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof VarInsnNode v && v.getOpcode() == Opcodes.ASTORE) {
                AbstractInsnNode p = v.getPrevious();
                while (p != null && p.getOpcode() < 0) p = p.getPrevious();
                String host = null;
                if (p instanceof MethodInsnNode ctor && isUrlValueOwner(ctor.owner)
                        && (ctor.name.equals("<init>") || ctor.name.equals("create"))) {
                    for (String lit : literalArgsInWindow(ctor, constLocals)) {
                        String hl = netHostLiteral(lit);
                        if (hl != null) { host = hl; break; }
                    }
                }
                // A non-URL store, a runtime-URL store (host==null), or a disagreeing host → ambiguous.
                if (host == null || (m.containsKey(v.var) && !m.get(v.var).equals(host))) {
                    ambiguous.add(v.var);
                    m.remove(v.var);
                } else if (!ambiguous.contains(v.var)) {
                    m.put(v.var, host);
                }
            }
        }
        return m;
    }

    /** Every String literal pushed in `call`'s OWN argument window — bounded at the statement start
     *  exactly like {@link #firstLiteralArg} (a prior call/branch/NEW/`*STORE`/PUT* ends the window). Used
     *  to attribute a host/SQL literal to the SPECIFIC host/SQL-bearing call that consumes it. The old
     *  method-wide LDC sweep captured ANY host/SQL-shaped string in a host/SQL-bearing method, so a benign
     *  URL literal certified a runtime-computed host (an AS-EFF-008 gate EVASION) and a SQL-shaped log line
     *  poisoned the table allowlist. Keyed to the call's own window, a literal in another statement is
     *  never captured — mirroring candor-rust's per-classified-call `str_arg` attribution. */
    static List<String> literalArgsInWindow(AbstractInsnNode call, Map<Integer, String> constLocals) {
        List<String> out = new ArrayList<>();
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode
                    || (n instanceof TypeInsnNode && n.getOpcode() == Opcodes.NEW)
                    || (n instanceof VarInsnNode v && v.getOpcode() >= Opcodes.ISTORE
                            && v.getOpcode() <= Opcodes.ASTORE)
                    || (n instanceof FieldInsnNode fi
                            && (fi.getOpcode() == Opcodes.PUTFIELD || fi.getOpcode() == Opcodes.PUTSTATIC)))
                break;
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) out.add(s);
            // Dataflow-lite: an arg that is a load of a PROVABLY-CONSTANT local (`String sql = "…"; q(sql)`)
            // resolves to its literal — the common "assign then use" shape the per-call window alone misses.
            // A load of a runtime/param local is NOT in constLocals, so the evasion stays killed (a benign
            // literal that never reaches the sink's arg slot is still never captured).
            else if (n instanceof VarInsnNode v && v.getOpcode() == Opcodes.ALOAD && constLocals.containsKey(v.var))
                out.add(constLocals.get(v.var));
        }
        return out;
    }

    /** Locals provably bound to a single String constant: an index whose EVERY `ASTORE` is fed directly by
     *  the SAME `LDC "…"`. An index ever stored a non-literal (a param, a method result, a concat) or two
     *  different literals is ambiguous and excluded — so resolving a load of one is sound (it is exactly that
     *  constant at every use). Used by {@link #literalArgsInWindow} to attribute a host/SQL literal that
     *  reaches the sink THROUGH a local, without re-introducing the method-wide over-capture. */
    static Map<Integer, String> constStringLocals(MethodNode mn) {
        Map<Integer, String> m = new HashMap<>();
        Set<Integer> ambiguous = new HashSet<>();
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof VarInsnNode v && v.getOpcode() == Opcodes.ASTORE) {
                AbstractInsnNode p = v.getPrevious();
                while (p != null && p.getOpcode() < 0) p = p.getPrevious(); // skip labels/frames/line-nos
                String s = (p instanceof LdcInsnNode ldc && ldc.cst instanceof String str) ? str : null;
                if (s == null || (m.containsKey(v.var) && !m.get(v.var).equals(s))) {
                    ambiguous.add(v.var);
                    m.remove(v.var);
                } else if (!ambiguous.contains(v.var)) {
                    m.put(v.var, s);
                }
            }
        }
        return m;
    }

    /** The literal int constant pushed closest before `call` — the port of a `(String host, int port)`
     *  Socket/InetSocketAddress ctor, for the SPEC §2 `host[:port]` surface. Null if the port is a runtime
     *  value (then no port is appended — the safe direction). Bounded to this call's arg window. */
    static String intLiteralBefore(AbstractInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            int op = n.getOpcode();
            if (op >= Opcodes.ICONST_0 && op <= Opcodes.ICONST_5) return String.valueOf(op - Opcodes.ICONST_0);
            if (n instanceof IntInsnNode iin && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) return String.valueOf(iin.operand);
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof Integer i) return String.valueOf(i);
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode) break;
        }
        return null;
    }

    /** The literal PROGRAM head a subprocess call NAMES — argv[0] specifically, never a later argument.
     *  Unlike {@link #firstLiteralArg} (the earliest literal ANYWHERE in the arg window), this refuses
     *  to refine when argv[0] is a runtime value but a trailing arg happens to be a literal whose
     *  basename hits the head table: `new ProcessBuilder(tool, "curl")` / `exec(new String[]{prog,
     *  "psql"})` must NOT fabricate Net/Db — the §1 under-report rule (mirrors candor-rust gating the
     *  refinement on a program-NAMING position via `is_cmd_naming_method`). The argv[0] shape is read
     *  from the call descriptor: a leading `String` is the scalar program (`Runtime.exec("curl …")`);
     *  a leading `String[]` is a varargs/array whose ELEMENT 0 is the program (`ProcessBuilder("curl",
     *  …)`, `exec(new String[]{"curl", …})`). Returns null whenever argv[0] is not a static literal —
     *  the safe direction. Used ONLY for the effect refinement, never to widen it. */
    static String programHeadLiteral(MethodInsnNode call) {
        boolean arrayHead = call.desc.startsWith("([Ljava/lang/String;");
        boolean scalarHead = call.desc.startsWith("(Ljava/lang/String;");
        if (!arrayHead && !scalarHead) return null; // a List<String> ctor etc. names no static head
        // The call's argument-evaluation window, bounded by a prior call/branch, real insns only
        // (drop labels/line-numbers/frames so the array-store pattern below is contiguous).
        List<AbstractInsnNode> win = new ArrayList<>();
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                break;
            if (n.getOpcode() >= 0) win.add(n); // skip pseudo-insns (opcode -1)
        }
        Collections.reverse(win); // evaluation order
        if (scalarHead) {
            // argv[0] is the FIRST value pushed (the instance receiver is a prior call/aload that the
            // window already excludes for the common `Runtime.getRuntime().exec(…)` form); it names a
            // program only if that first value is itself a String literal.
            if (win.isEmpty()) return null;
            AbstractInsnNode first = win.get(0);
            return (first instanceof LdcInsnNode ldc && ldc.cst instanceof String s) ? s : null;
        }
        // arrayHead: argv[0] is element 0 of the leading String[]. javac emits initializers in index
        // order, so the FIRST `ICONST_0, <elem>, AASTORE` in the window is that store — element 0 of
        // the command array (even in the two-array `exec(String[], String[] envp)` overload, where the
        // command array is built before envp). The head is static only if <elem> is a String literal.
        for (int i = 0; i + 2 < win.size(); i++) {
            if (win.get(i).getOpcode() == Opcodes.ICONST_0 && win.get(i + 2).getOpcode() == Opcodes.AASTORE) {
                AbstractInsnNode v = win.get(i + 1);
                return (v instanceof LdcInsnNode ldc && ldc.cst instanceof String s) ? s : null;
            }
        }
        return null;
    }

    /** The String literal CLOSEST to a call — its last-pushed String arg. For `getMethod("y")` the
     *  name is pushed immediately before the call, so the nearest String is unambiguously it; the
     *  loose firstLiteralArg (keep-earliest) would grab an unrelated prior constant (`String tag =
     *  "runIt"; … c.getMethod("strip")` returned "runIt" — a fabricated target). */
    static String nearestLiteralArg(MethodNode mn, AbstractInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                return null;
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof String s) return s; // NEAREST
        }
        return null;
    }

    /** The receiver Class type of a reflective `X.class.getMethod("y")` — the nearest `LDC X.class`
     *  Type constant before the call (internal slash-form), bounded by a prior call/branch. Null when
     *  the receiver is a RUNTIME Class value (`obj.getClass()`, a field): then the reflection target
     *  is genuinely indeterminate and an edge MUST NOT be fabricated (the §4 Unknown stands). */
    static String reflectReceiver(MethodNode mn, AbstractInsnNode call) {
        for (AbstractInsnNode n = call.getPrevious(); n != null; n = n.getPrevious()) {
            if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode || n instanceof JumpInsnNode)
                return null; // a prior call (e.g. getClass()) or branch bounds the receiver evaluation
            if (n instanceof LdcInsnNode ldc && ldc.cst instanceof org.objectweb.asm.Type t
                    && t.getSort() == org.objectweb.asm.Type.OBJECT)
                return t.getInternalName();
        }
        return null;
    }

    /** Whether a path-constructor descriptor takes the path as a SINGLE leading String — `(String)` or
     *  `(String, String...)` (Path.of's varargs) — so the FIRST string literal is unambiguously the
     *  path. Excludes two-String overloads (`File(String,String)`, `RandomAccessFile(String,String)`)
     *  whose second String (child name / mode) could be the only literal when the path is computed. */
    static boolean pathArgIsSingleString(String desc) {
        String head = "(Ljava/lang/String;";
        return desc.startsWith(head)
                && desc.length() > head.length()
                && (desc.charAt(head.length()) == ')' || desc.charAt(head.length()) == '[');
    }

    /** The program a command literal names (`/usr/bin/git` → `git`), so `allow Exec … git` accepts an
     *  absolute path to it. Mirrors the Rust `cmd_base`, plus: `Runtime.exec(String)` passes a whole
     *  command LINE ("curl http://x"), so take the first whitespace token (the program) before the
     *  basename — `ProcessBuilder` literals are already a bare program. */
    static String cmdBase(String c) {
        String first = c.trim().split("\\s+", 2)[0];
        int i = Math.max(first.lastIndexOf('/'), first.lastIndexOf('\\'));
        return i >= 0 ? first.substring(i + 1) : first;
    }

    /** Refine the `Exec` cliff (spec §4 ⟨0.5⟩): the effects a literal, statically-known subprocess
     *  head implies, matched by basename. ADDED to a caller that already carries `Exec` (a subprocess
     *  is still spawned — `Exec` is never dropped); an unrecognised head returns {} and keeps the bare
     *  cliff (never guess). A **candor engine** reads Fs/Env only — spec §7 item 12 (the analyzer
     *  self-boundary) guarantees that, so that case is spec-supplied, not curation. The reference
     *  engines share this table verbatim so the `Exec` boundary refines identically. INVARIANT: every
     *  head is an external tool that does NOT run the analysed project's own code (so make/npm/cargo
     *  are deliberately absent — they keep the cliff). Mirrors candor-rust's `classify_command_head`. */
    static Set<String> commandHeadEffects(String cmd) {
        // Only UNAMBIGUOUS single-effect tools belong here. A multi-modal head (`git status` local vs
        // `git push` Net; `rsync` local vs remote) would FABRICATE the effect for its common case —
        // the under-report rule forbids it, so such heads keep the bare cliff.
        switch (cmdBase(cmd)) {
            case "curl": case "wget": case "http": case "ssh": case "scp":
            case "sftp": case "ftp": case "telnet":
                return Set.of("Net");
            case "psql": case "mysql": case "sqlite3": case "mongosh": case "mongo":
            case "redis-cli": case "cqlsh": case "influx":
                return Set.of("Db");
            case "candor": case "candor-run.sh": case "candor-scan": case "candor-query":
            case "candor-java": case "candor-classify": case "candor-report": case "cargo-candor":
                return Set.of("Env", "Fs"); // §7 item 12: analyzers do Fs/Env only
            default:
                return Set.of();
        }
    }

    /** Whether an allowed dir `a` covers the reached path `r` at a COMPONENT boundary (so `/etc/app`
     *  covers `/etc/app/cfg` but not `/etc/apppwned`); a `..` in the reached path is never covered.
     *  Mirrors the Rust `fs_path_covered`, including the absolute-vs-relative rootedness check. */
    static boolean pathCovered(String a, String r) {
        java.util.function.Function<String, List<String>> norm = s -> {
            List<String> out = new ArrayList<>();
            for (String c : s.split("[/\\\\]")) if (!c.isEmpty() && !c.equals(".")) out.add(c);
            return out;
        };
        if (norm.apply(r).contains("..")) return false;
        boolean aAbs = a.startsWith("/") || a.startsWith("\\");
        boolean rAbs = r.startsWith("/") || r.startsWith("\\");
        if (aAbs != rAbs) return false;
        List<String> ac = norm.apply(a), rc = norm.apply(r);
        if (ac.size() > rc.size()) return false;
        for (int i = 0; i < ac.size(); i++) if (!ac.get(i).equals(rc.get(i))) return false;
        return true;
    }

    /** Whether an allowed table entry `a` covers a reached table `r`: case-insensitive exact match
     *  on the (possibly schema-qualified) name, or a `schema.*` entry covering every table in that
     *  schema. Strict on qualification (an allowed `entries` does NOT cover `ledger.entries`).
     *  Mirrors the Rust `db_table_covered`. */
    static boolean tableCovered(String a, String r) {
        a = a.toLowerCase(); r = r.toLowerCase();
        if (a.endsWith(".*")) {
            String schema = a.substring(0, a.length() - 2);
            return r.startsWith(schema + ".");
        }
        return a.equals(r);
    }

    /** Table-position identifiers in a SQL string literal — the `Db` literal surface (SPEC §2
     *  `tables`). Conservative by construction (a wrong capture would FABRICATE): the string must
     *  open with a SQL statement keyword; only FROM/JOIN/INTO (anywhere), statement-leading
     *  UPDATE/TRUNCATE, and TABLE take the following identifier, skipping ONLY/IF NOT EXISTS;
     *  `FOR UPDATE SKIP LOCKED` yields nothing (mid-statement UPDATE ignored). Mirrors the Rust
     *  `tables_in_sql` token-for-token — SPEC §2 pins the algorithm and the cross-impl vector
     *  battery (candor-spec conformance/tables/vectors.json, run.sh Part 4b) enforces it. */
    static List<String> tablesInSql(String sql) {
        Set<String> stmt = Set.of("select", "insert", "update", "delete", "create", "drop", "alter",
                "truncate", "merge", "replace", "with");
        Set<String> skip = Set.of("only", "if", "not", "exists", "table");
        Set<String> stop = Set.of("select", "set", "where", "values", "on", "using", "group", "order",
                "by", "limit", "returning", "as", "inner", "outer", "left", "right", "cross", "lateral",
                "natural", "union", "all", "distinct", "case", "when", "null", "default", "skip",
                "nowait", "of", "from", "join", "into", "update", "delete", "insert");
        // `,` survives as its OWN token: it lets `FROM t1, t2` continue the table list without
        // fabricating from other comma-ridden positions (column lists, ON clauses).
        String cleaned = sql.toLowerCase().replaceAll("[();]", " ").replace(",", " , ");
        // "\\s+" (regex any-whitespace), NOT "\s+" — the latter is the Java 15 *space escape*, which
        // splits on literal spaces only and glues tokens across the newlines of formatted SQL.
        String[] toks = cleaned.trim().split("\\s+");
        List<String> out = new ArrayList<>();
        if (toks.length == 0 || !stmt.contains(toks[0])) return out;
        java.util.function.Function<String, String> ident = (raw) -> {
            String t = raw.replaceAll("^[\"'`]+|[\"'`]+$", "");
            if (t.isEmpty() || stop.contains(t)) return null;
            char c0 = t.charAt(0);
            if (!(Character.isLetter(c0) || c0 == '_')) return null;
            if (!t.matches("[a-z_][a-z0-9_.$\"`]*")) return null;
            return t.replaceAll("[\"`]", "");
        };
        for (int i = 0; i < toks.length; i++) {
            String tok = toks[i];
            boolean tablePos = tok.equals("from") || tok.equals("join") || tok.equals("into")
                    || tok.equals("table")
                    || ((tok.equals("update") || tok.equals("truncate")) && i == 0);
            if (!tablePos) continue;
            int j = i + 1;
            while (j < toks.length && skip.contains(toks[j])) j++;
            if (j >= toks.length) continue;
            String first = ident.apply(toks[j]);
            if (first == null) continue;
            if (!out.contains(first)) out.add(first);
            // Comma-ADJACENT continuation only: `FROM t1, t2, t3` takes all three, while an alias
            // breaks the chain (`FROM t1 a, t2` keeps just t1 — an under-report, never a guess:
            // skipping an alias to chase the comma would fabricate tables out of
            // `INSERT INTO t (a, b)`'s column list, whose parens are spaces by now).
            while (j + 2 < toks.length && toks[j + 1].equals(",")) {
                String more = ident.apply(toks[j + 2]);
                if (more == null) break;
                if (!out.contains(more)) out.add(more);
                j += 2;
            }
        }
        return out;
    }
}
