package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * SPEC §6.2 ⟨0.41⟩ — {@code candor accepts [--report <locator>] [--policy <file>] [--json] [--adopt --because <reason>]}:
 * refreshing (or adopting) {@code accept} lines as a PROPOSED policy.
 *
 * <p><b>THE CARDINAL DIRECTION IS ACCEPTING A VIOLATION THAT IS NEW, AND THIS VERB CAN ONLY ACCEPT LESS.</b> It
 * therefore decides nothing itself: every fact it uses — which entry is stale, accepted, exceeded, ambiguous,
 * unjudged or ignored, and which rows a rule line produced — is read from THIS ENGINE'S OWN GATE
 * ({@link Query#gate}) run over the same bytes, so "the same parse and the same matching" holds by construction and
 * not by a second implementation that could drift. The proposed text is then gated again to report {@code after}.
 * An entry whose state the gate did not name is KEPT, never deleted.
 *
 * <p>It writes no file. The gate is fed the policy text through {@link Policy#virtualPolicies}, under a name beside
 * the policy (so {@code .candor/config} vocabulary anchors the same way) that is never created on disk.
 */
final class Accepts {
    private Accepts() {}

    private static final Set<String> RULE_KINDS = Set.of("deny", "pure", "forbid", "allow", "only");
    private static final String MARK = "# candor-accepts:";
    private static final String REPLACE = " — REPLACE the line above with: ";

    /** One input line: its bytes (kept verbatim), its terminator (kept verbatim) and the text the gate reads. */
    private record Ln(byte[] body, byte[] term, String text) {}

    /** One violation row, as the gate's verdict carried it. */
    private record Row(String rule, String fn, String hash, List<String> effects, List<String> classes) {
        String key() { return rule + "\u0000" + fn + "\u0000" + String.join(",", new TreeSet<>(effects)); }
    }

    private record Gated(int rc, JsonObject doc, String err) {}

    private static int vseq = 0;

    // ------------------------------------------------------------------------------------------------
    // lines
    // ------------------------------------------------------------------------------------------------
    /** Split at LF, CRLF or a lone CR — the SAME terminators {@link Files#readAllLines} splits at, because the gate's
     *  {@code line} numbers must be this verb's line numbers. Every byte lands in exactly one body or terminator. */
    private static List<Ln> split(byte[] b) {
        List<Ln> out = new ArrayList<>();
        int start = 0, n = b.length;
        for (int i = 0; i < n; ) {
            byte c = b[i];
            if (c == '\n' || c == '\r') {
                int tl = (c == '\r' && i + 1 < n && b[i + 1] == '\n') ? 2 : 1;
                out.add(mk(Arrays.copyOfRange(b, start, i), Arrays.copyOfRange(b, i, i + tl), out.isEmpty()));
                i += tl;
                start = i;
            } else {
                i++;
            }
        }
        if (start < n) out.add(mk(Arrays.copyOfRange(b, start, n), new byte[0], out.isEmpty()));
        return out;
    }

    private static Ln mk(byte[] body, byte[] term, boolean first) {
        String t = new String(body, StandardCharsets.UTF_8);
        if (first && !t.isEmpty() && t.charAt(0) == '﻿') t = t.substring(1);   // readPolicyLines drops a leading BOM
        return new Ln(body, term, t);
    }

    private static byte[] u8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    private static String[] lex(String text) {
        String l = text.split("#", 2)[0].trim();
        return l.isEmpty() ? new String[0] : l.split("\\s+");
    }

    private static boolean isMark(String text) {
        return text.stripLeading().startsWith(MARK) && text.substring(0, text.length() - text.stripLeading().length())
                .chars().allMatch(c -> c == ' ' || c == '\t');
    }

    private static String commentOf(String text) {
        int i = text.indexOf('#');
        return i < 0 ? "" : " " + text.substring(i);
    }

    // ------------------------------------------------------------------------------------------------
    // gating
    // ------------------------------------------------------------------------------------------------
    private static Gated gate(List<String> reports, String vpath, List<String> lines) {
        Policy.virtualPolicies.put(vpath, lines);
        PrintStream out0 = System.out, err0 = System.err;
        ByteArrayOutputStream ob = new ByteArrayOutputStream(), eb = new ByteArrayOutputStream();
        int rc;
        try {
            System.setOut(new PrintStream(ob, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(eb, true, StandardCharsets.UTF_8));
            rc = Query.gate(reports, null, vpath, true, null);
        } finally {
            System.setOut(out0);
            System.setErr(err0);
            Policy.virtualPolicies.remove(vpath);
        }
        JsonObject doc = null;
        try {
            JsonElement e = JsonParser.parseString(ob.toString(StandardCharsets.UTF_8));
            if (e.isJsonObject()) doc = e.getAsJsonObject();
        } catch (RuntimeException ignore) { /* no document: treated as a refusal below */ }
        return new Gated(rc, doc, eb.toString(StandardCharsets.UTF_8));
    }

    private static List<Row> rows(JsonObject doc) {
        List<Row> out = new ArrayList<>();
        if (doc == null || !doc.has("violations")) return out;
        for (JsonElement e : doc.getAsJsonArray("violations")) {
            JsonObject v = e.getAsJsonObject();
            String rule = str(v, "rule");
            if (!"AS-EFF-006".equals(rule) && !"AS-EFF-009".equals(rule)) continue;
            out.add(new Row(rule, str(v, "fn"), str(v, "hash"), strs(v, "effects"), strs(v, "reasonClass")));
        }
        return out;
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : null;
    }

    private static List<String> strs(JsonObject o, String k) {
        List<String> out = new ArrayList<>();
        if (o.has(k) && o.get(k).isJsonArray()) for (JsonElement e : o.getAsJsonArray(k)) out.add(e.getAsString());
        return out;
    }

    private static List<String> canon(Collection<String> concrete, Collection<String> classes) {
        List<String> t = new ArrayList<>(concrete);
        if (classes != null) t.add("Unknown[" + String.join(",", sortedCp(new HashSet<>(classes))) + "]");
        t.sort(Query.BY_CODE_POINT);
        return t;
    }

    private static List<String> sortedCp(Collection<String> c) {
        List<String> l = new ArrayList<>(c);
        l.sort(Query.BY_CODE_POINT);
        return l;
    }

    // ------------------------------------------------------------------------------------------------
    // the verb
    // ------------------------------------------------------------------------------------------------
    static int run(List<String> reports, String policyPath, boolean adopt, String because, boolean json) {
        if (policyPath == null) policyPath = Query.resolvePolicyFallback();
        if (policyPath == null) {
            System.err.println("candor accepts: a policy is required — pass `--policy <file>` or set CANDOR_POLICY.");
            return 2;
        }
        byte[] raw;
        try {
            raw = Files.readAllBytes(Path.of(policyPath));
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw));
        } catch (CharacterCodingException e) {
            System.err.println("candor accepts: cannot read policy " + policyPath + " (not valid UTF-8) — no proposal.");
            return 2;
        } catch (java.io.IOException | RuntimeException e) {
            System.err.println("candor accepts: cannot read policy " + policyPath + " (" + e.getMessage() + ") — no proposal.");
            return 2;
        }
        List<Ln> in = split(raw);
        List<String> pol = new ArrayList<>();
        for (Ln l : in) pol.add(l.text());
        int n = pol.size();
        String vpath = Path.of(policyPath).toAbsolutePath().resolveSibling(".candor-accepts-virtual-" + (++vseq)).toString();

        // ---- 1. the gate over the input bytes ---------------------------------------------------------
        Accept.forceTwins = true;
        Gated g0;
        List<Accept.Entry> entries;
        Map<Integer, List<Accept.Row>> direct;
        Set<String> twins;
        Map<String, Set<String>> callers;
        Set<Integer> stale;
        try {
            g0 = gate(reports, vpath, pol);
            entries = new ArrayList<>(Accept.entries);
            direct = Accept.directSnapshot();
            twins = Accept.twinSnapshot();
            callers = Accept.callersSnapshot();
            stale = Accept.staleLines();
        } finally {
            Accept.forceTwins = false;
        }
        JsonObject d = g0.doc();
        boolean answered = (g0.rc() == 0 || g0.rc() == 1) && d != null && d.has("violations")
                && !(d.has("refused") && d.get("refused").getAsBoolean());
        boolean incomplete = d != null && d.has("incomplete") && d.get("incomplete").getAsBoolean();
        if (!answered || incomplete) {
            String err = g0.err().replace(Path.of(vpath).getFileName().toString(), Path.of(policyPath).getFileName().toString());
            System.err.print(err);
            System.err.println("candor accepts: the gate over this policy and report " + (incomplete
                    ? "is INCOMPLETE (a unit it did not read makes its entries look stale, and pruning them would delete the reasons "
                    + "for code that still exists)" : "refuses (exit " + g0.rc() + ")") + " — no proposal. The policy was not changed.");
            boolean anyRule = false;
            for (String t : pol) { String[] k = lex(t); if (k.length > 0 && RULE_KINDS.contains(k[0])) { anyRule = true; break; } }
            if (!anyRule)
                System.err.println("candor accepts: this policy holds no rules. If it was empty because you ran "
                        + "`candor accepts > " + policyPath + "`, a shell redirect onto the policy EMPTIES it before the verb "
                        + "reads it — the policy file is now empty; restore it (e.g. `git checkout -- " + policyPath
                        + "`) and write the proposal to ANOTHER path, then diff.");
            return 2;
        }

        // ---- 2. what each entry is -----------------------------------------------------------------------
        Set<Integer> ignored = new TreeSet<>();
        if (d.has("ignored"))
            for (JsonElement e : d.getAsJsonArray("ignored")) {
                int ln = e.getAsJsonObject().get("line").getAsInt();
                if (ln >= 1 && ln <= n && lex(pol.get(ln - 1)).length > 0 && lex(pol.get(ln - 1))[0].equals("accept")) ignored.add(ln);
            }
        Map<Integer, String> status = new HashMap<>();
        if (d.has("accepted"))
            for (JsonElement e : d.getAsJsonArray("accepted")) {
                JsonObject it = e.getAsJsonObject();
                if (it.has("enclosing")) continue;
                status.put(it.get("line").getAsInt(), it.get("status").getAsString());
            }
        Map<Integer, String> ruleTok = new LinkedHashMap<>();             // rule line -> its tokens, single-spaced
        for (int i = 1; i <= n; i++) {
            String[] k = lex(pol.get(i - 1));
            if (k.length > 0 && RULE_KINDS.contains(k[0])) ruleTok.put(i, String.join(" ", k));
        }
        // rows each deny/pure rule line produced ALONE (accept lines and the other rules withheld)
        Map<Integer, List<Row>> per = new HashMap<>();
        for (int L : ruleTok.keySet()) {
            String k0 = lex(pol.get(L - 1))[0];
            if (!k0.equals("deny") && !k0.equals("pure")) { per.put(L, List.of()); continue; }
            List<String> lines = new ArrayList<>();
            for (int i = 1; i <= n; i++) {
                String[] k = lex(pol.get(i - 1));
                if (k.length > 0 && k[0].equals("accept")) lines.add("# (accept line withheld)");
                else if (k.length > 0 && RULE_KINDS.contains(k[0]) && i != L) lines.add("# (rule line withheld)");
                else lines.add(pol.get(i - 1));
            }
            per.put(L, rows(gate(reports, vpath, lines).doc()));
        }

        // ---- 3. the changes ---------------------------------------------------------------------------------
        Map<Integer, Map<String, Object>> removed = new LinkedHashMap<>(), narrowed = new LinkedHashMap<>(),
                proposals = new LinkedHashMap<>();
        List<Map<String, Object>> unjudged = new ArrayList<>();
        Map<Integer, String> newText = new HashMap<>();                   // narrowed line -> rewritten text
        Map<Integer, String> proposalComment = new HashMap<>();
        for (Accept.Entry e : entries) {
            int L = e.line();
            String st = status.getOrDefault(L, stale.contains(L) ? "stale" : "kept");
            List<Integer> myLines = new ArrayList<>();
            for (var r : ruleTok.entrySet()) if (r.getValue().equals(e.ruleKey())) myLines.add(r.getKey());
            switch (st) {
                case "stale" -> removed.put(L, item(L, e.fn(), e.ruleKey(), e.because()));
                case "accepted" -> {
                    TreeSet<String> conc = new TreeSet<>(), cls = new TreeSet<>();
                    boolean unk = false;
                    for (Accept.Row r : direct.getOrDefault(L, List.of())) {
                        for (String x : r.effects) { if (x.equals("Unknown")) unk = true; else conc.add(x); }
                        cls.addAll(r.classes);
                    }
                    List<String> to = canon(conc, unk ? (cls.isEmpty() && e.classes() != null ? e.classes() : cls) : null);
                    TreeSet<String> fromConc = new TreeSet<>(e.effects()); fromConc.remove("Unknown");
                    List<String> from = canon(fromConc, e.classes());
                    if (!new HashSet<>(to).equals(new HashSet<>(from))) {
                        Map<String, Object> m = item(L, e.fn(), e.ruleKey(), e.because());
                        String text = "accept " + e.fn() + " " + String.join(" ", to) + " for " + e.ruleKey() + " because "
                                + e.because() + commentOf(pol.get(L - 1));
                        m.put("from", from);
                        m.put("to", to);
                        m.put("text", text);
                        narrowed.put(L, m);
                        newText.put(L, text);
                    }
                }
                case "exceeded" -> {
                    TreeSet<String> conc = new TreeSet<>(), cls = new TreeSet<>();
                    boolean unk = false;
                    for (int ml : myLines)
                        for (Row r : per.getOrDefault(ml, List.of()))
                            if (r.fn().equals(e.fn())) {
                                for (String x : r.effects()) { if (x.equals("Unknown")) unk = true; else conc.add(x); }
                                cls.addAll(r.classes());
                            }
                    if (unk && cls.isEmpty()) {
                        // SPEC §6.2 ⟨0.41⟩: no class to name, so no line could cover the row — keep the line, propose nothing.
                        System.err.println("candor accepts: line " + L + " (`" + e.fn() + "`) is EXCEEDED by an `Unknown` whose reason classes "
                                + "this report does not carry — no wider line can be written for it; kept as is, and the row stays red.");
                        continue;
                    }
                    List<String> prop = canon(conc, unk ? cls : null);
                    TreeSet<String> have = new TreeSet<>(e.effects()); have.remove("Unknown");
                    List<String> adds = new ArrayList<>();
                    for (String x : conc) if (!have.contains(x)) adds.add(x);
                    if (unk) {
                        TreeSet<String> extra = new TreeSet<>(cls);
                        if (e.classes() != null) extra.removeAll(e.classes());
                        if (!extra.isEmpty()) adds.add("Unknown[" + String.join(",", sortedCp(extra)) + "]");
                    }
                    adds = sortedCp(adds);
                    String text = "accept " + e.fn() + " " + String.join(" ", prop) + " for " + e.ruleKey() + " because "
                            + e.because() + commentOf(pol.get(L - 1));
                    Map<String, Object> m = item(L, e.fn(), e.ruleKey(), e.because());
                    m.put("adds", adds);
                    m.put("text", text);
                    proposals.put(L, m);
                    proposalComment.put(L, MARK + " exceeded (adds " + String.join(" ", adds) + ")" + REPLACE + text);
                }
                case "unjudged" -> unjudged.add(item(L, e.fn(), e.ruleKey(), null));
                default -> {
                    /* ambiguous, or a state the gate did not name: kept byte for byte — and said, so the row it leaves red has a cause */
                    System.err.println("candor accepts: line " + L + " (`" + e.fn() + "`) is " + st.toUpperCase(java.util.Locale.ROOT)
                            + " — two units share that name with different hashes, so the entry accepts NEITHER; kept as written. "
                            + "Remedy: rename one of the two, or gate the modules separately.");
                }
            }
        }
        List<Map<String, Object>> ignoredOut = new ArrayList<>();
        for (int L : ignored) { Map<String, Object> m = new LinkedHashMap<>(); m.put("line", L); ignoredOut.add(m); }

        // ---- adoption candidates: the rows no entry names (computed in both modes: `unnamed`) ---------------------
        record Cand(int line, String fn, String hash, String rule, List<String> effects) {}
        List<Cand> cands = new ArrayList<>();
        Map<String, TreeSet<String>> refused = new LinkedHashMap<>();   // reason key -> the fns no entry could be written for
        Set<String> seen = new HashSet<>();
        for (Row v : rows(d)) {
            List<Integer> prod = new ArrayList<>();
            for (var pe : per.entrySet())
                for (Row w : pe.getValue())
                    if (w.key().equals(v.key()) && java.util.Objects.equals(w.hash(), v.hash())) { prod.add(pe.getKey()); break; }
            prod.sort(null);
            for (int L : prod) {
                String rule = ruleTok.get(L);
                boolean named = false;
                for (Accept.Entry e : entries) if (e.fn().equals(v.fn()) && e.ruleKey().equals(rule)) named = true;
                if (named || !seen.add(rule + "\u0000" + v.fn())) continue;
                if (twins.contains(v.fn())) { refuse(refused, "twin", v.fn()); continue; }
                if (Accept.positional(v.fn())) { refuse(refused, "positional", v.fn()); continue; }
                if (v.fn().chars().anyMatch(c -> c == '#' || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == 0x0B)) {
                    refuse(refused, "unwritable", v.fn()); continue;
                }
                TreeSet<String> conc = new TreeSet<>(v.effects());
                boolean unk = conc.remove("Unknown");
                if (unk && v.classes().isEmpty()) { refuse(refused, "noclass", v.fn()); continue; }
                cands.add(new Cand(L, v.fn(), v.hash(), rule, canon(conc, unk ? v.classes() : null)));
            }
        }
        cands.sort((a, b) -> a.line() != b.line() ? Integer.compare(a.line(), b.line()) : Query.BY_CODE_POINT.compare(a.fn(), b.fn()));
        List<Map<String, Object>> unnamed = new ArrayList<>(), created = new ArrayList<>();
        List<String> createdText = new ArrayList<>();
        for (Cand c : cands) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("fn", c.fn());
            if (c.hash() != null && !c.hash().isEmpty()) m.put("hash", c.hash());
            m.put("policyRule", c.rule());
            m.put("effects", c.effects());
            unnamed.add(m);
            if (adopt) {
                String text = "accept " + c.fn() + " " + String.join(" ", c.effects()) + " for " + c.rule() + " because " + because;
                Map<String, Object> cm = new LinkedHashMap<>();
                cm.put("fn", c.fn());
                if (c.hash() != null && !c.hash().isEmpty()) cm.put("hash", c.hash());
                cm.put("policyRule", c.rule());
                cm.put("because", because);
                cm.put("effects", c.effects());
                cm.put("text", text);
                created.add(cm);
                createdText.add(text);
            }
        }

        // ---- 4. the proposed text ---------------------------------------------------------------------------------
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 1; i <= n; i++) {
            Ln l = in.get(i - 1);
            if (isMark(l.text()) || removed.containsKey(i)) continue;
            if (newText.containsKey(i)) {
                out.writeBytes(u8(newText.get(i)));
                out.writeBytes(l.term());
            } else {
                out.writeBytes(l.body());
                out.writeBytes(l.term());
            }
            if (proposalComment.containsKey(i)) {
                if (l.term().length == 0) out.writeBytes(u8("\n"));
                out.writeBytes(u8(proposalComment.get(i)));
                if (l.term().length > 0) out.writeBytes(l.term());
            }
        }
        byte[] body = out.toByteArray();
        if (!createdText.isEmpty()) {
            ByteArrayOutputStream o2 = new ByteArrayOutputStream();
            o2.writeBytes(body);
            if (body.length > 0 && body[body.length - 1] != '\n' && body[body.length - 1] != '\r') o2.writeBytes(u8("\n"));
            for (String t : createdText) o2.writeBytes(u8(t + "\n"));
            body = o2.toByteArray();
        }
        String text = new String(body, StandardCharsets.UTF_8);

        // ---- 5. `after`: the gate's verdict over the proposal --------------------------------------------------------
        List<String> after = new ArrayList<>();
        List<Ln> pl = split(body);
        for (Ln l : pl) after.add(l.text());
        Gated g1 = gate(reports, vpath, after);
        int acc = 0, viol = 0;
        if (g1.doc() != null) {
            if (g1.doc().has("violations")) viol = g1.doc().getAsJsonArray("violations").size();
            if (g1.doc().has("accepted"))
                for (JsonElement e : g1.doc().getAsJsonArray("accepted"))
                    if ("accepted".equals(str(e.getAsJsonObject(), "status"))) acc++;
        }
        Map<String, Object> aft = new LinkedHashMap<>();
        aft.put("exit", g1.rc());
        aft.put("violations", viol);
        aft.put("accepted", acc);

        // ---- 6. output ---------------------------------------------------------------------------------------------
        PrintStream so = System.out;
        if (json) {
            Map<String, Object> plan = new LinkedHashMap<>();
            plan.put("mode", adopt ? "adopt" : "refresh");
            plan.put("text", text);
            plan.put("removed", new ArrayList<>(removed.values()));
            plan.put("narrowed", new ArrayList<>(narrowed.values()));
            plan.put("proposals", new ArrayList<>(proposals.values()));
            if (adopt) plan.put("created", created);
            plan.put("unnamed", unnamed);
            plan.put("unjudged", unjudged);
            plan.put("ignored", ignoredOut);
            plan.put("after", aft);
            byte[] pj = u8(Query.JSON.toJson(plan) + "\n");
            so.write(pj, 0, pj.length);
        } else {
            so.write(body, 0, body.length);
        }
        so.flush();
        System.err.println("candor accepts (" + (adopt ? "adopt" : "refresh") + "): " + removed.size() + " stale line(s) removed, "
                + narrowed.size() + " narrowed, " + proposals.size() + " exceeded (proposed in a comment, NOT accepted), "
                + created.size() + " created; " + unnamed.size() + " violation(s) no entry names; after the proposal the gate exits "
                + g1.rc() + " with " + viol + " violation(s), " + acc + " accepted.");
        for (Map<String, Object> u : unjudged)
            System.err.println("candor accepts: line " + u.get("line") + " (`" + u.get("fn") + "` under `" + u.get("policyRule")
                    + "`) kept UNJUDGED — this route cannot evaluate that rule, so nothing is known about the entry. Gate at scan time.");
        for (int L : ignored)
            System.err.println("candor accepts: line " + L + " is IGNORED by the gate and kept as written — repairing it is yours.");
        printRefused(refused, callers);
        System.err.println("candor accepts: nothing was written. To take the proposal: write it to ANOTHER path (not onto the policy — "
                + "a shell redirect onto it empties it first), then `diff " + policyPath + " <that path>` and commit.");
        return 0;
    }

    private static void refuse(Map<String, TreeSet<String>> m, String why, String fn) {
        m.computeIfAbsent(why, k -> new TreeSet<>(Query.BY_CODE_POINT)).add(fn);
    }

    /** ⟨0.41.1⟩ Every violation the proposal leaves red because NO line could be written for it — with the reason and the remedy,
     *  so "after the proposal the gate exits 1 with N violation(s)" is never a number with no cause. Human channel only: the
     *  plan document is unchanged. Up to five names per reason, then a count. */
    private static void printRefused(Map<String, TreeSet<String>> refused, Map<String, Set<String>> callers) {
        // a positional row no accept line can ever cover gets its own sentence (creating function, what works); the rest keep the generic one
        TreeSet<String> pos = refused.get("positional");
        if (pos != null) {
            TreeSet<String> rest = new TreeSet<>(Query.BY_CODE_POINT);
            TreeSet<String> notes = new TreeSet<>(Query.BY_CODE_POINT);
            for (String f : pos) { String n = Accept.uncoverableNote(f, callers); if (n != null) notes.add(n); else rest.add(f); }
            if (rest.isEmpty()) refused.remove("positional"); else refused.put("positional", rest);
            int k = 0;
            for (String n : notes) {
                if (k++ == 5) { System.err.println("candor accepts: … and " + (notes.size() - 5) + " more violation(s) no `accept` line can cover."); break; }
                System.err.println("candor accepts: no accept line is written for " + n);
            }
        }
        String[][] why = {
            {"positional", "keyed by POSITION (an anonymous class `Foo$1`, a lambda `lambda$…`), which an `accept` line cannot name — a renumbering would re-point it at a different unit",
                "give it a NAME (extract the anonymous class to a named one, a lambda to a named method), re-scan, and run `accepts` again; or fix the violation"},
            {"twin", "a (hash, fn) TWIN — two units with this name and different hashes, so no line could name one of them",
                "rename one of the two, or gate the modules separately; or fix the violation"},
            {"unwritable", "named with a `#` or whitespace, which cannot be written on a policy line",
                "rename it, or fix the violation"},
            {"noclass", "carries an `Unknown` whose reason class this report does not carry, so no `Unknown[…]` line would cover it",
                "re-scan with the current engine so the report carries its reason classes, then run `accepts` again; or fix the violation"},
        };
        for (String[] w : why) {
            TreeSet<String> fns = refused.get(w[0]);
            if (fns == null || fns.isEmpty()) continue;
            List<String> shown = new ArrayList<>();
            for (String f : fns) { if (shown.size() == 5) break; shown.add("`" + f + "`"); }
            System.err.println("candor accepts: " + fns.size() + " violation(s) get NO accept line — " + w[1] + ": " + String.join(", ", shown)
                    + (fns.size() > shown.size() ? ", … and " + (fns.size() - shown.size()) + " more" : "") + ". Remedy: " + w[2] + ".");
        }
    }

    private static Map<String, Object> item(int line, String fn, String rule, String because) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("line", line);
        m.put("fn", fn);
        m.put("policyRule", rule);
        if (because != null) m.put("because", because);
        return m;
    }

    /** Validate {@code --because} per §6.2: one argument, lexed by ASCII whitespace; at least one token; no {@code #}.
     *  Returns the single-spaced reason, or null after printing the usage error. */
    static String reason(String raw) {
        List<String> toks = new ArrayList<>();
        for (String t : raw.split("[ \t\n\r\f\u000B]+")) if (!t.isEmpty()) toks.add(t);
        if (toks.isEmpty()) {
            System.err.println("candor accepts: --because needs a reason — a value with at least one token.");
            return null;
        }
        if (raw.indexOf('#') >= 0) {
            System.err.println("candor accepts: --because must not contain `#` — a `#` begins a comment on a policy line, so it would cut "
                    + "the reason you wrote short. Reword it (the issue number without the hash, say).");
            return null;
        }
        return String.join(" ", toks);
    }
}
