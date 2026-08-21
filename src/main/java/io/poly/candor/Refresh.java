package io.poly.candor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

/** THE REPORT REFRESH — re-analyse only the classes whose bytecode changed.
 *
 *  <p>Why it exists: the agent edit-time loop pays a full re-analysis every time one class changes. On
 *  the field case (uflexi, 2,259 classes) that is 3.30s of a 3.51s Stop-hook, and it is the turn the
 *  agent is waiting on. The frequency half is already handled — the hook skips turns where nothing the
 *  verdict depends on moved — so what remains is the first turn after any edit.
 *
 *  <p>WHAT IS CACHED, AND WHY ONLY THAT. Measured with CANDOR_TIMING across three targets: parse+analyze
 *  is ~90% of a scan, the fixpoint 1.3–3.4%, the whole-program indexes ~37 ms. So the per-class work is
 *  cached and everything else is recomputed every run. The closure especially: a callee's new effect
 *  changes callers that did not themselves change, which is the entire point of the tool, and at 3.4%
 *  it is never worth the risk of serving a stale one.
 *
 *  <p>THE SAFETY CONTRACT. A stale entry read as current is a silent under-report inside a
 *  normal-looking report — this project's cardinal sin — so every step fails closed:
 *
 *  <ul>
 *    <li>entries are keyed on CONTENT, never mtime. The Stop-hook's own skip guard may use mtime safely
 *        because a wrong skip there self-corrects on the next turn; a wrong cache hit does not.</li>
 *    <li>a different ENGINE BUILD discards the whole cache, because a classifier fix must not be
 *        silently skipped — the same rule §2.1 already applies to dependency reports and baselines.</li>
 *    <li>a change to any class's STRUCTURE, or to any whole-program pre-pass output, or to the policy,
 *        flags or chained dependencies, discards the whole cache. See {@link #wholeProgramDigest}.</li>
 *    <li>anything unreadable, unrecognised or unparseable abandons the cache and takes the full scan.
 *        There is no path on which the refresh guesses.</li>
 *  </ul>
 *
 *  <p>Its acceptance test is byte equality with a cold scan, over the report AND every sidecar:
 *  bin/refresh-equiv.sh, whose control arm is what stops a blind replay from passing.
 */
final class Refresh {

    /** Bumped when the on-disk shape changes. An older file is discarded, never migrated: a cache is
     *  rebuildable by definition, so migration code would be risk with nothing on the other side. */
    private static final String FORMAT = "candor-refresh-1";

    private final Path file;                  // null when caching is off
    private final Map<String, JsonObject> loaded = new HashMap<>();   // internal name -> stored entry
    private final JsonObject out = new JsonObject();                  // what this run will store
    private final Map<String, String> hashes;  // internal name -> content hash, from the loader
    private String digest;                    // the whole-program digest this run computed
    private int reused, total;
    private boolean poisoned;                 // a delta refused to serialise: store nothing this run
    private boolean dirty;                    // a class was analysed afresh, so the file must be rewritten

    private static final Refresh DISABLED = new Refresh(null, Map.of());

    private Refresh(Path file, Map<String, String> hashes) {
        this.file = file;
        this.hashes = hashes;
    }

    /** A scan with no cache: every class is analysed, nothing is stored. The overlay split still runs —
     *  see the analyze loop in {@link Candor} for why there is only ever one path. */
    static Refresh disabled() {
        return DISABLED;
    }

    static Refresh forScan(Config cfg, List<ClassNode> classes) {
        String spec = cfg == null ? null : cfg.value("refresh", "CANDOR_REFRESH");
        if (spec == null || spec.isEmpty() || spec.equals("0")) return DISABLED;
        Map<String, String> hashes = AnalysisState.ctx().classHash;
        // Without a content hash per class there is no sound key, and the fallback is a full scan
        // rather than a weaker key: an mtime or a name would be exactly the "looks fine, is stale"
        // failure this whole class is arranged to avoid.
        if (hashes.size() < classes.size()) {
            warn("no content hash for " + (classes.size() - hashes.size()) + " of " + classes.size()
                    + " class(es) — scanning in full");
            return DISABLED;
        }
        Refresh r;
        try {
            Path dir = Path.of(spec);
            Files.createDirectories(dir);
            r = new Refresh(dir.resolve(FORMAT + ".json"), hashes);
            r.digest = wholeProgramDigest(classes);
            Candor.phase("cache-digest");
            r.load();
            Candor.phase("cache-load");
        } catch (Exception e) {
            warn("cache unusable (" + e + ") — scanning in full");
            return DISABLED;
        }
        return r;
    }

    private void load() {
        if (!Files.isReadable(file)) return;
        try {
            JsonObject root = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
            // THE THREE INVALIDATIONS, all whole-cache. A partial invalidation would need a rule for
            // which entries a given change can reach, and getting that rule subtly wrong is precisely
            // how a cache serves a stale answer.
            if (!FORMAT.equals(str(root, "format"))) return;
            if (!ReportWriter.release().equals(str(root, "engine"))) return;
            if (!digest.equals(str(root, "program"))) return;
            JsonObject cs = root.getAsJsonObject("classes");
            if (cs == null) return;
            for (var e : cs.entrySet()) loaded.put(e.getKey(), e.getValue().getAsJsonObject());
        } catch (Exception e) {
            loaded.clear();   // an unreadable or malformed cache is simply no cache
        }
    }

    /** True when this class's delta came from the cache and {@code analyze} can be skipped. */
    boolean replayInto(ClassNode cn, AnalysisContext overlay) {
        if (file == null) return false;
        total++;
        JsonObject e = loaded.get(cn.name);
        if (e == null) return false;
        String want = hashes.get(cn.name);
        if (want == null || !want.equals(str(e, "hash"))) return false;
        try {
            Delta.decode(e.getAsJsonObject("delta"), overlay);
        } catch (Exception ex) {
            // A delta that will not decode is not a reason to guess. Re-analysing is always available
            // and always correct, so take it and say so.
            warn("cached entry for " + cn.name + " did not decode (" + ex + ") — re-analysing it");
            return false;
        }
        out.add(cn.name, e);       // unchanged; carry it forward verbatim
        reused++;
        return true;
    }

    /** Take this class's freshly-computed delta for storage. */
    void record(ClassNode cn, AnalysisContext overlay) {
        if (file == null || poisoned || out.has(cn.name)) return;
        String h = hashes.get(cn.name);
        if (h == null) return;
        try {
            JsonObject e = new JsonObject();
            e.addProperty("hash", h);
            e.add("delta", Delta.encode(overlay));
            out.add(cn.name, e);
            dirty = true;
        } catch (AnalysisContext.UnmergeableDelta ex) {
            // An accumulator this build cannot serialise means every FUTURE run from this cache would
            // silently drop it. Storing a partial cache would be the under-report; storing nothing
            // costs only speed, so the whole run's cache is abandoned and the reason is printed.
            poisoned = true;
            warn("cannot store a delta for " + cn.name + " (" + ex.getMessage() + ") — this scan's "
                    + "results are correct, but nothing will be cached until that field is handled");
        }
    }

    /** Persist what the scan learned, and disclose the reuse.
     *
     *  <p>The disclosure is not decoration: bin/refresh-equiv.sh REQUIRES a non-zero reuse before it will
     *  believe its own comparison. Against a build where the cache silently never engages, every arm of
     *  that harness is a cold scan compared with a cold scan and it passes while measuring nothing. */
    void finish() {
        if (file == null) return;
        System.err.println("candor-java: refresh — reused " + reused + " of " + total
                + " class(es) from " + file);
        if (poisoned) return;
        // Nothing was analysed afresh and nothing dropped out, so the file on disk is already exactly
        // what this run would write. On the field case that file is 15 MB, and rewriting it is pure
        // cost on the run the whole feature exists to make fast — the unchanged-tree run.
        if (!dirty && out.size() == loaded.size()) return;
        try {
            JsonObject root = new JsonObject();
            root.addProperty("format", FORMAT);
            root.addProperty("engine", ReportWriter.release());
            root.addProperty("program", digest);
            root.add("classes", out);
            // Atomic replace: a crash mid-write must not leave a half-file that a later run reads as a
            // cache. It would be discarded as malformed, but only because that path happens to exist.
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, root.toString());
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Candor.phase("cache-write");
        } catch (Exception e) {
            warn("could not write the cache (" + e + ") — this scan's results are unaffected");
        }
    }

    // ---- the whole-program key ----

    /** Everything a class's analysis depends on BESIDES that class's own bytes, reduced to one digest.
     *  Any change to it discards the entire cache.
     *
     *  <p>It covers every class's STRUCTURE — name, supertypes, access, and the name/descriptor/access
     *  and annotations of every method and field — because dispatch resolution, the overload index and
     *  the entry-point rules all read other classes' shapes. It also covers the whole-program pre-pass
     *  OUTPUTS explicitly, rather than trusting that structure implies them: {@code suppressibleStreamFields}
     *  is computed from method BODIES, so a digest over structure alone would miss it, and "derivable
     *  from something already covered" is the kind of reasoning that is right until one field is not.
     *  Config, flags, policy and the chained dependency set are in it for the same reason.
     *
     *  <p>THE ONE ASSUMPTION LEFT is that analysing class A never reads another class's instruction
     *  BODIES — if it did, editing B's body would leave A's cached delta stale while this digest held
     *  still. That is not left as a comment: RefreshBodyIndependenceTest measures it directly, by
     *  analysing every class twice, once against the real program and once against a program whose
     *  other bodies have been stripped, and requiring the two deltas to be equal.
     */
    private static String wholeProgramDigest(List<ClassNode> classes) {
        StringBuilder sb = new StringBuilder();
        List<ClassNode> sorted = new ArrayList<>(classes);
        sorted.sort(Comparator.comparing(c -> c.name));
        for (ClassNode c : sorted) {
            sb.append(c.name).append('\u0001').append(c.superName).append('\u0001')
              .append(c.access).append('\u0001').append(String.join(",", c.interfaces)).append('\u0001')
              .append(c.signature).append('\u0001');
            annos(sb, c.visibleAnnotations); annos(sb, c.invisibleAnnotations);
            List<MethodNode> ms = new ArrayList<>(c.methods);
            ms.sort(Comparator.<MethodNode, String>comparing(m -> m.name).thenComparing(m -> m.desc));
            for (MethodNode m : ms) {
                sb.append('\u0002').append(m.access).append(':').append(m.name).append(':')
                  .append(m.desc).append(':').append(m.signature).append(':')
                  .append(m.exceptions == null ? "" : String.join(",", m.exceptions));
                annos(sb, m.visibleAnnotations); annos(sb, m.invisibleAnnotations);
            }
            List<FieldNode> fs = new ArrayList<>(c.fields);
            fs.sort(Comparator.<FieldNode, String>comparing(f -> f.name).thenComparing(f -> f.desc));
            for (FieldNode f : fs) {
                sb.append('\u0003').append(f.access).append(':').append(f.name).append(':')
                  .append(f.desc).append(':').append(f.signature).append(':').append(f.value);
                annos(sb, f.visibleAnnotations); annos(sb, f.invisibleAnnotations);
            }
            sb.append('\n');
        }
        AnalysisContext c = AnalysisState.ctx();
        sb.append("prepass");
        sb.append(new TreeSet<>(c.suppressibleStreamFields)).append('\u0001')
          .append(new TreeSet<>(c.repoTypes)).append('\u0001')
          .append(new TreeMap<>(c.entityTables)).append('\u0001')
          .append(new TreeMap<>(c.repoTables)).append('\u0001')
          .append(new TreeSet<>(c.feignTypes)).append('\u0001')
          .append(new TreeSet<>(c.httpClientTypes)).append('\u0001')
          .append(new TreeSet<>(c.classesWithClinit)).append('\u0001');
        sb.append("deps");
        sb.append(new TreeSet<>(c.crossDeps.keySet())).append('\u0001')
          .append(new TreeSet<>(c.depCoveredPkgs)).append('\u0001')
          .append(new TreeSet<>(c.depChainedPkgs)).append('\u0001')
          .append(new TreeMap<>(c.depSupers)).append('\u0001')
          .append(new TreeSet<>(c.depSplitKnown)).append('\u0001')
          .append(new TreeMap<>(c.depSuperclass)).append('\u0001')
          .append(c.depReportsRead).append('\u0001');
        sb.append("flags");
        sb.append(c.taintEnabled).append(c.closedWorld).append(c.unknownRatchet).append(c.peekVersioned)
          .append('\u0001').append(new TreeSet<>(c.netPartners)).append('\u0001')
          .append(c.unknownAliases).append('\u0001')
          .append(c.denyRules).append(c.allowRules).append(c.forbidRules).append(c.onlyRules);
        // CANDOR_REFRESH_DEBUG=<file>: dump the digest's INPUT, so a cache that misses can be diffed
        // instead of theorised about. A digest tells you two runs disagree and nothing about where.
        String dbg = System.getenv("CANDOR_REFRESH_DEBUG");
        if (dbg != null && !dbg.isEmpty()) {
            try { Files.writeString(Path.of(dbg), sb.toString()); } catch (Exception ignored) { }
        }
        // A DIGEST CONTAINING AN IDENTITY HASH IS NOT A DIGEST. Every value folded in above must be
        // value-based, and the one that was not — ASM's String[] enum encoding — cost a debugging
        // session and would have been read as "the cache works" on any run whose allocation order
        // happened to repeat. Rather than re-audit each field whenever one is added, look for the
        // shape: `ClassName@1b6d3586` is what Object.toString() produces and nothing else here does.
        // Finding one abandons the cache for a full scan, which is always correct and always available.
        java.util.regex.Matcher m = IDENTITY_HASH.matcher(sb);
        if (m.find()) throw new IllegalStateException("the whole-program digest contains an identity "
                + "hash (" + m.group() + "): some value is rendered by Object.toString(), so the digest "
                + "would differ on every JVM run and the cache could never hit. Render it structurally.");
        return sha256(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static final char SEP = '\u0001';

    /** {@code some.Class@1b6d3586} — what {@code Object.toString()} emits, and the tell that a
     *  non-value-based rendering has reached the digest. See the check in {@link #wholeProgramDigest}. */
    private static final java.util.regex.Pattern IDENTITY_HASH =
            java.util.regex.Pattern.compile("[\\w.$\\[;]+@[0-9a-f]{6,8}\\b");

    private static void annos(StringBuilder sb, List<AnnotationNode> as) {
        if (as == null) return;
        List<String> descs = new ArrayList<>();
        for (AnnotationNode a : as) descs.add(a.desc + "=" + annoValue(a.values));
        Collections.sort(descs);
        sb.append('@').append(String.join("|", descs));
    }

    /** Render an annotation value STRUCTURALLY.
     *
     *  <p>MEASURED, and it is the reason this method exists rather than a {@code toString()}: ASM
     *  encodes an enum constant as a {@code String[]} and an array-valued attribute as a {@code List},
     *  so {@code String.valueOf(values)} yields {@code [Ljava.lang.String;@2ef5e5e3} — an IDENTITY HASH.
     *  The digest was therefore different on every JVM run, the key never matched, and the cache never
     *  hit once.
     *
     *  <p>Two things about how that presented are worth keeping. It failed in the SAFE direction — a
     *  cache that never hits is a full scan — which is exactly why it could have lived here a long time.
     *  And it did not look random: identity hashes follow allocation order, so consecutive runs of the
     *  same shape produced the SAME digest and the cache appeared to work, while a run preceded by a
     *  different run did not. A three-run check would have called it fixed.
     *
     *  <p>What caught it was the reuse count. The byte-equality arm cannot: a cache that always misses
     *  produces byte-identical reports, so equivalence passes perfectly while the feature does nothing.
     *  That is precisely why bin/refresh-equiv.sh refuses to conclude anything without a non-zero reuse. */
    private static String annoValue(Object v) {
        if (v == null) return "null";
        if (v instanceof String[] enumRef) return "E" + Arrays.toString(enumRef);
        if (v instanceof AnnotationNode nested) return "@" + nested.desc + annoValue(nested.values);
        if (v instanceof List<?> l) {
            StringBuilder b = new StringBuilder("[");
            for (Object x : l) b.append(annoValue(x)).append(',');
            return b.append(']').toString();
        }
        if (v.getClass().isArray()) {
            StringBuilder b = new StringBuilder("{");
            int n = java.lang.reflect.Array.getLength(v);
            for (int i = 0; i < n; i++) b.append(annoValue(java.lang.reflect.Array.get(v, i))).append(',');
            return b.append('}').toString();
        }
        return String.valueOf(v);   // primitives, String, org.objectweb.asm.Type — all value-based
    }

    static String sha256(byte[] b) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            StringBuilder sb = new StringBuilder();
            for (byte x : md.digest(b)) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o == null ? null : o.get(k);
        return e == null || e.isJsonNull() ? null : e.getAsString();
    }

    private static void warn(String m) {
        System.err.println("candor-java: refresh — " + m);
    }

    /** THE SPLIT'S OWN VERIFICATION (CANDOR_REFRESH_VERIFY). Off by default because it costs a pass over
     *  the shared inputs per scan; on in the test suite and in bin/refresh-equiv.sh, where it is the
     *  check that an accumulator has not been misfiled as a shared input — the one error mode a cold
     *  byte-equality comparison structurally cannot see, because on a cold run the misfiled writes still
     *  reach the master and the answer still comes out right. */
    static boolean verifying() {
        String v = System.getenv("CANDOR_REFRESH_VERIFY");
        return v != null && !v.isEmpty() && !v.equals("0");
    }

    // ---- delta encoding ----

    /** Encodes and decodes one class's accumulators.
     *
     *  <p>Reflective over the same {@code final}-means-output fact the overlay split uses, so a field
     *  added later is carried without anyone editing this class. Every value type it does not recognise
     *  RAISES — a codec that skipped an unfamiliar value would drop that accumulator on every refresh,
     *  which is the silent under-report the cache exists to not commit. Empty collections are omitted
     *  entirely: the merge already treats absent as empty, which conveniently means an empty field
     *  never needs a type tag at all.
     */
    static final class Delta {

        static JsonObject encode(AnalysisContext o) {
            JsonObject j = new JsonObject();
            for (var f : AnalysisContext.outputFields()) {
                Object v;
                try { v = f.get(o); } catch (IllegalAccessException e) { throw new AnalysisContext.UnmergeableDelta(f.getName() + ": " + e); }
                if (v == null) continue;
                if (v instanceof Map<?, ?> m) {
                    if (m.isEmpty()) continue;
                    JsonObject mo = new JsonObject();
                    for (var e : m.entrySet()) {
                        if (!(e.getKey() instanceof String k))
                            throw new AnalysisContext.UnmergeableDelta(f.getName() + ": non-String key " + e.getKey());
                        mo.add(k, val(f.getName(), e.getValue()));
                    }
                    j.add(f.getName(), mo);
                } else if (v instanceof Collection<?> c) {
                    if (c.isEmpty()) continue;
                    j.add(f.getName(), val(f.getName(), c));
                } else {
                    throw new AnalysisContext.UnmergeableDelta("accumulator '" + f.getName() + "' is a "
                            + v.getClass().getName() + ", which the refresh codec cannot encode");
                }
            }
            return j;
        }

        @SuppressWarnings("unchecked")
        static void decode(JsonObject j, AnalysisContext o) {
            if (j == null) throw new AnalysisContext.UnmergeableDelta("missing delta");
            for (var f : AnalysisContext.outputFields()) {
                JsonElement e = j.get(f.getName());
                if (e == null) continue;
                Object cur;
                try { cur = f.get(o); } catch (IllegalAccessException x) { throw new AnalysisContext.UnmergeableDelta(f.getName() + ": " + x); }
                if (cur instanceof Map<?, ?>) {
                    Map<Object, Object> dst = (Map<Object, Object>) cur;
                    for (var en : e.getAsJsonObject().entrySet()) dst.put(en.getKey(), unval(f.getName(), en.getValue()));
                } else if (cur instanceof Collection<?>) {
                    ((Collection<Object>) cur).addAll((Collection<Object>) unval(f.getName(), e));
                } else {
                    throw new AnalysisContext.UnmergeableDelta("accumulator '" + f.getName()
                            + "' is not a collection on decode");
                }
            }
        }

        /** A tagged value. The tag names the CONCRETE collection class, not just "a set": a TreeSet and a
         *  HashSet iterate differently, and iteration order reaches the report's bytes — so restoring the
         *  wrong one is a diff in the acceptance test rather than a silent problem, but restoring it
         *  right is free. */
        private static JsonElement val(String field, Object v) {
            if (v instanceof String s) return new JsonPrimitive("s" + s);
            if (v instanceof Integer i) return new JsonPrimitive("i" + i);
            if (v instanceof EffectSet es) return arr("e", es.toNames());
            if (v instanceof String[] sa) return arr("a", Arrays.asList(sa));
            if (v instanceof Collection<?> c) {
                String tag = v instanceof TreeSet<?> ? "T" : v instanceof LinkedHashSet<?> ? "K"
                        : v instanceof Set<?> ? "H" : v instanceof List<?> ? "L" : null;
                if (tag == null) throw new AnalysisContext.UnmergeableDelta("accumulator '" + field
                        + "' is a " + v.getClass().getName() + ", which the refresh codec cannot encode");
                // The ELEMENT kind travels with the collection kind: a TreeSet of reasons and a TreeSet
                // of strings restore differently, and the pair lists (reflectPairs, deferredForcePairs)
                // hold String[] rows. That last case is the one that first refused to encode — correctly,
                // rather than dropping the deferred-forwarding bookkeeping from every later refresh.
                Object first = c.isEmpty() ? null : c.iterator().next();
                String kind = first instanceof UnknownReason ? "u" : first instanceof String[] ? "a" : "s";
                JsonArray a = new JsonArray();
                a.add(tag + kind);
                for (Object x : c) {
                    if (x instanceof String s) a.add(s);
                    else if (x instanceof UnknownReason u) a.add(u.format());
                    else if (x instanceof String[] row) { JsonArray r = new JsonArray(); for (String s : row) r.add(s); a.add(r); }
                    else throw new AnalysisContext.UnmergeableDelta("accumulator '" + field + "' holds a "
                            + x.getClass().getName() + " element, which the refresh codec cannot encode");
                }
                return a;
            }
            throw new AnalysisContext.UnmergeableDelta("accumulator '" + field + "' holds a "
                    + v.getClass().getName() + " value, which the refresh codec cannot encode");
        }

        private static Object unval(String field, JsonElement e) {
            if (e.isJsonPrimitive()) {
                String s = e.getAsString();
                if (s.startsWith("s")) return s.substring(1);
                if (s.startsWith("i")) return Integer.valueOf(s.substring(1));
                throw new AnalysisContext.UnmergeableDelta("accumulator '" + field + "': bad scalar tag");
            }
            JsonArray a = e.getAsJsonArray();
            String tag = a.get(0).getAsString();
            if (tag.equals("e")) {
                List<String> names = new ArrayList<>();
                for (int i = 1; i < a.size(); i++) names.add(a.get(i).getAsString());
                return EffectSet.ofNames(names);
            }
            if (tag.equals("a")) {
                String[] row = new String[a.size() - 1];
                for (int i = 1; i < a.size(); i++) row[i - 1] = a.get(i).getAsString();
                return row;
            }
            Collection<Object> c = switch (tag.charAt(0)) {
                case 'T' -> new TreeSet<>();
                case 'K' -> new LinkedHashSet<>();
                case 'H' -> new HashSet<>();
                case 'L' -> new ArrayList<>();
                default -> throw new AnalysisContext.UnmergeableDelta("accumulator '" + field + "': bad tag " + tag);
            };
            String kind = tag.substring(1);
            for (int i = 1; i < a.size(); i++) {
                JsonElement x = a.get(i);
                switch (kind) {
                    case "u" -> c.add(UnknownReason.parse(x.getAsString()));
                    case "a" -> {
                        JsonArray r = x.getAsJsonArray();
                        String[] row = new String[r.size()];
                        for (int k = 0; k < r.size(); k++) row[k] = r.get(k).getAsString();
                        c.add(row);
                    }
                    case "s" -> c.add(x.getAsString());
                    default -> throw new AnalysisContext.UnmergeableDelta("accumulator '" + field + "': bad element tag " + tag);
                }
            }
            return c;
        }

        private static JsonElement arr(String tag, Collection<String> items) {
            JsonArray a = new JsonArray();
            a.add(tag);
            for (String s : items) a.add(s);
            return a;
        }
    }
}
