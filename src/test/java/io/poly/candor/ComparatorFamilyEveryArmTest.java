package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;
import io.poly.candor.model.UnknownReason;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R236 — {@code Comparator} AND ITS FAMILY WERE OUTSIDE EVERY ARM THAT CHARGES A CALLBACK, SO
 * {@code xs.sort(cmpField)} AND A DIRECT {@code cmp.compare(a, b)} WERE BOTH SILENT.
 *
 * <p><b>THE DEFECT, GROUND TRUTH EXECUTED against a jar built at {@code 9dfd5d2}.</b> Eighteen probe
 * methods whose callback really writes a file are ABSENT from {@code functions[]}, and
 * {@code deny Unknown <method>} exits 0 "no violations" on every one of them, against exit 1 on
 * {@code removeIf(pParam)} in the same class. The set that decides three of the four arms was
 * {@code java/util/function/} + {@code Runnable} + {@code Callable}; {@code Comparator},
 * {@code FileFilter}, {@code FilenameFilter} and the two {@code PrivilegedAction}s were only ever in the
 * WIDER set, which gates the two arms that resolve a NAMED impl. So a comparator got an edge when it
 * arrived as {@code new MyCmp()} and nothing at all in every other spelling.
 *
 * <p><b>THE DIRECT-INVOKE CELL IS WHY THIS IS ITS OWN ROW AND NOT A GAP IN R217's.</b> R217's mechanism
 * is "an argument handed to an invoking higher-order function". {@code cmpParam.compare("a","b")} fires
 * with no higher-order function anywhere: it is {@code handleMethodInsn}'s unpinned-SAM branch, keyed on
 * {@code Candor#isJdkFunctionalSam}, one frame shallower. A fix bolted onto R217's opaque arm alone
 * could not have reached it — and R217 MEASURED that: the wider set in that arm alone cost +1,697 rows
 * over 395 jars (596 in assertj-core, 560 in jandex) and still left the direct invoke silent, so it was
 * rejected. The set was never the problem; asking it in one arm out of four was.
 *
 * <p><b>WHAT CHANGED: ONE SET, ASKED BY EVERY ARM.</b> {@code Candor#isHofFunctionalIface} is gone and
 * {@code Candor#isFunctionalIface} is the single membership authority, consulted by the direct-invoke
 * branch (through {@code isJdkFunctionalSam}), by R183's creation-site arm, by R217's opaque arm, by
 * {@code namedFunctionalToHof} and by {@code functionalSamSurface}. The SAM NAME is asked of
 * {@code Candor#samNameOf} — R191's JDK-derived index — rather than written down a second time (§G),
 * which is what keeps {@code Comparator}'s eleven {@code default}/{@code static} members
 * ({@code reversed}, {@code thenComparing}, {@code comparing}, …) out of it.
 *
 * <p><b>WHICH DIRECTION IT FAILS IN, SAID BEFORE THE CHANGE.</b> Widening an interface set can only ADD
 * {@code Unknown}. The one arm that can move the other way is
 * {@code Candor#singleFunctionalParamIndex}, which returns -1 for MORE than one functional parameter — a
 * wider set can only turn an index into -1, and -1 means the disclosure is emitted NOW instead of being
 * deferred and resolved from call sites. So {@code REMOVED} over the corpus had to be 0.
 *
 * <p><b>A/B OVER 395 GRADLE-CACHE JARS (347 with rows; 48 are annotation-only and scan to zero rows in
 * BOTH engines), KEYED ON EVERY FIELD, 578,461 COMMON ROWS: ADDED 2,077, REMOVED 0,
 * CHANGED(every field) 2,814, CHANGED(inferred) 534.</b> Instrumented, because an unchanged row is not
 * evidence the new code ran: 1,368 events at 734 distinct sites, across all four arms
 * (opaque 573, fwdparam 83, direct 23, indy 1 — distinct sites). No channel lost an entry anywhere
 * except {@code overdeclared} (130 rows), which is {@code declared - performed} shrinking because
 * {@code performed} grew — a precision gain, and the same benign channel R217 measured. Every one of the
 * 534 {@code inferred} moves is a strict addition of exactly {@code Unknown}; no added row claims a
 * concrete effect. Bucketed from {@code javap}, never from candor's own report: pcollections'
 * {@code KVTree} really does {@code invokeinterface Comparator.compare} on a caller-supplied comparator
 * at seven sites, which is where its 358 rows come from; commons-io's {@code FileUtils.listFiles(File,
 * FileFilter)} really hands the caller's filter to {@code File.listFiles}; jandex's {@code Type.<init>}
 * really sorts with one.
 *
 * <p><b>RESIDUAL, STATED NOT IMPLIED.</b> An opaque callback whose {@code declType} names a class that is
 * IN THE SCAN is hedged rather than resolved — junit's {@code Sorter.orderItems} passes {@code this} to
 * {@code Collections.sort} and gets {@code Unknown} although {@code Sorter.compare} is right there. That
 * is R217's residual (3) one interface over, and it stays: {@code declType} is a sound over-approximation
 * source whose own contract forbids using it to NARROW.
 */
class ComparatorFamilyEveryArmTest {

    /** The write is the ground truth: callbacks that really touch the filesystem when they run. */
    private static final String EFF = String.join("\n",
        "package app;",
        "import java.nio.file.*;",
        "public class Eff {",
        "  public static void touch() { try { Files.writeString(",
        "      Paths.get(System.getProperty(\"candor.r236.witness\")), \"x\",",
        "      StandardOpenOption.CREATE, StandardOpenOption.APPEND); }",
        "    catch (Exception e) { throw new RuntimeException(e); } }",
        "}");

    /** THE DEFECT. Every callback arrives OPAQUELY (a parameter or a field) or is invoked DIRECTLY, and
     *  NO class in this fixture implements any of the interfaces — so CHA is empty and a disclosure is
     *  the only honest answer. No method name is a prefix of another, so a scoped policy over them
     *  cannot inherit the prefix-matching contamination the 0.35.0 panel recorded. */
    private static final String CMP = String.join("\n",
        "package app;",
        "import java.io.*;",
        "import java.security.*;",
        "import java.util.*;",
        "public class Cmp {",
        "  private Comparator<String> cf;",
        "  public void bind(Comparator<String> c) { this.cf = c; }",
        "  public void hofParam(List<String> xs, Comparator<String> c)   { xs.sort(c); }",
        "  public void hofField(List<String> xs)                         { xs.sort(this.cf); }",
        "  public int directParam(Comparator<String> c)                  { return c.compare(\"a\", \"b\"); }",
        "  public int directField()                                      { return this.cf.compare(\"a\", \"b\"); }",
        "  public int streamMin(List<String> xs, Comparator<String> c)   { return xs.stream().min(c).get().length(); }",
        "  public void arraySort(String[] a, Comparator<String> c)       { Arrays.sort(a, c); }",
        "  public File[] listFilter(File d, FileFilter f)                { return d.listFiles(f); }",
        "  public boolean nameFilterDirect(FilenameFilter f, File d)     { return f.accept(d, \"x\"); }",
        "  @SuppressWarnings({\"deprecation\",\"removal\"})",
        "  public String priv(PrivilegedAction<String> p)                { return AccessController.doPrivileged(p); }",
        "  public String privDirect(PrivilegedAction<String> p)          { return p.run(); }",
        "}");

    private static final String DRIVE = String.join("\n",
        "package app;",
        "import java.io.*;",
        "import java.nio.file.*;",
        "import java.util.*;",
        "public class Drive { public static void main(String[] a) throws Exception {",
        "  Comparator<String> c = (x, y) -> { Eff.touch(); return x.compareTo(y); };",
        "  Cmp h = new Cmp(); h.bind(c);",
        "  h.hofParam(new ArrayList<>(List.of(\"b\",\"a\")), c);",
        "  h.hofField(new ArrayList<>(List.of(\"b\",\"a\")));",
        "  h.directParam(c);",
        "  h.directField();",
        "  h.streamMin(List.of(\"b\",\"a\"), c);",
        "  h.arraySort(new String[]{\"b\",\"a\"}, c);",
        "  File d = Files.createTempDirectory(\"candor-r236\").toFile();",
        "  h.listFilter(d, f -> { Eff.touch(); return true; });",
        "  h.nameFilterDirect((dir, n) -> { Eff.touch(); return true; }, d);",
        "  h.priv(() -> { Eff.touch(); return \"x\"; });",
        "  h.privDirect(() -> { Eff.touch(); return \"x\"; });",
        "  d.delete();",
        "} }");

    /** Ten driven arms; {@code listFilter} runs the filter once per directory entry and the directory is
     *  empty, so it contributes no write — it is asserted on the SCAN, not on the count. */
    private static final String[] ARMS = {
        "hofParam", "hofField", "directParam", "directField", "streamMin", "arraySort",
        "listFilter", "nameFilterDirect", "priv", "privDirect"};

    private static Map<String, String> fixture() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Eff.java", EFF);
        m.put("app/Cmp.java", CMP);
        m.put("app/Drive.java", DRIVE);
        return m;
    }

    /** RED WITHOUT THE FIX: all ten arms are ABSENT from the report on a jar built at {@code 9dfd5d2}.
     *
     *  <p>§E3/§J — GROUND TRUTH EXECUTED, and kept separate from what is only analysed. Nine of the ten
     *  arms are RUN and really perform the effect; the tenth ({@code listFilter}) runs its filter over an
     *  empty directory, so it is asserted on the scan alone and this comment says so rather than letting
     *  the count imply otherwise.
     *
     *  <p>DISCRIMINATING: reverting {@code isFunctionalIface} to the pre-R236 three-owner set reddens
     *  every assertion here. */
    @Test
    void everyArmChargesTheComparatorFamily() throws Exception {
        Path cls = compile(fixture());
        try {
            Path witness = Files.createTempFile("candor-r236", ".txt");
            Files.delete(witness);
            String saved = System.getProperty("candor.r236.witness");
            System.setProperty("candor.r236.witness", witness.toString());
            try (URLClassLoader cl = new URLClassLoader(new URL[]{cls.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                cl.loadClass("app.Drive").getMethod("main", String[].class).invoke(null, (Object) new String[0]);
            } finally {
                if (saved == null) System.clearProperty("candor.r236.witness");
                else System.setProperty("candor.r236.witness", saved);
            }
            assertTrue(Files.exists(witness) && Files.readString(witness).length() >= 9,
                "the driven arms must really perform the effect, or every row below is measured against "
                + "a program that does not do what this row says it does. Got "
                + (Files.exists(witness) ? Files.readString(witness) : "<no witness file>"));
            Files.deleteIfExists(witness);

            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : ARMS)
                assertTrue(eff(r, "app.Cmp." + m).contains(Effect.UNKNOWN),
                    m + " reaches a caller-supplied callback that really runs — Comparator, FileFilter, "
                    + "FilenameFilter and PrivilegedAction are functional interfaces exactly as "
                    + "java.util.function's are, and nothing here pins this one to any visible body. Got "
                    + r.get("app.Cmp." + m));
        } finally { rm(cls.getParent()); }
    }

    /** THE CELL THAT MAKES THIS ITS OWN ROW. {@code c.compare(a, b)} on a parameter is not a hand-off to
     *  anything — there is no higher-order function in the method at all — so R217's arm, which reads the
     *  ARGUMENTS of an invoking library HOF, can never see it. It is the unpinned-SAM branch of
     *  {@code handleMethodInsn}, and the reason it must be the SAME set is right here: charging
     *  {@code hofParam} while {@code directParam} stayed silent would put the boundary somewhere no arm
     *  agrees, which is precisely why R217 declined to widen its own arm alone.
     *
     *  <p>DISCRIMINATING: this row is the one that stays RED if the set is widened for the opaque arm
     *  only — the fix R217 built, measured and rejected. */
    @Test
    void theDirectInvokeCellHasNoHigherOrderFunctionAtAll() throws Exception {
        Path cls = compile(Map.of("app/Direct.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "public class Direct {",
            "  public int viaDirect(Comparator<String> c) { return c.compare(\"a\", \"b\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Direct.viaDirect").contains(Effect.UNKNOWN),
                "no higher-order function is involved: the comparator is invoked directly, one frame "
                + "shallower than R217's arm can see. Got " + r.get("app.Direct.viaDirect"));
            assertEquals("[callback:java.util.Comparator.compare]", whyOf("app.Direct.viaDirect"),
                "and the reason names the interface the JDK really invokes");
        } finally { rm(cls.getParent()); }
    }

    /** THE OVER-CHARGE CONTROL, AND IT IS BUILT TO SURVIVE THE TRAP R217 RECORDED. R217's first draft of
     *  this control used {@code Objects.requireNonNull(f)} / {@code Optional.ofNullable(f)} /
     *  {@code Stream.of(f)} / {@code list.add(f)}, every one of which ERASES its parameter to
     *  {@code Object} — so the interface gate excluded them before the guard under test was ever
     *  consulted, and it read as coverage of the allowlist while being coverage of erasure. Every sink
     *  below takes a genuinely {@code Comparator}/{@code FileFilter}-TYPED parameter and never invokes
     *  it: {@code reversed}/{@code thenComparing}/{@code comparing} are {@code Comparator}'s own
     *  {@code default} and {@code static} members, {@code new TreeMap<>(cmp)} and the field write STORE
     *  it, and {@code FileFilter} reaches a constructor.
     *
     *  <p>DEGRADED AND CONFIRMED RED: keying the SAM on {@code samNameOf} alone rather than on
     *  {@code FUNCTION_PKG_SAM}-then-{@code samNameOf} does not move it, but making
     *  {@code isJdkFunctionalSam} return true for ANY method of a recognised owner reddens
     *  {@code combinators}, and dropping the {@code isInvokingHof} gate reddens {@code stores}. */
    @Test
    void combinatorsFactoriesAndStoresGainNothing() throws Exception {
        Path cls = compile(Map.of("app/Sink.java", String.join("\n",
            "package app;",
            "import java.io.*;",
            "import java.util.*;",
            "import java.util.function.*;",
            "public class Sink {",
            "  private Comparator<String> held;",
            "  private FileFilter ff;",
            "  public Comparator<String> combinators(Comparator<String> a, Comparator<String> b) {",
            "    return a.reversed().thenComparing(b); }",
            "  public Comparator<String> factory(Function<String,String> k) { return Comparator.comparing(k); }",
            "  public Map<String,String> stores(Comparator<String> c) { this.held = c; return new TreeMap<>(c); }",
            "  public void keepFilter(FileFilter f) { this.ff = f; }",
            "  public int compareStrings(String a, String b) { return a.compareTo(b); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"combinators", "factory", "stores", "keepFilter", "compareStrings"})
                assertFalse(eff(r, "app.Sink." + m).contains(Effect.UNKNOWN),
                    m + " takes a genuinely Comparator/FileFilter-TYPED parameter (so the interface gate "
                    + "really is consulted here, unlike an Object-erased sink) and never invokes it. "
                    + "Charging it would be the fabrication the invoker allowlist exists to prevent. Got "
                    + r.get("app.Sink." + m));
        } finally { rm(cls.getParent()); }
    }

    /** A PROVABLE {@code null} HANDS OVER NO CALLBACK. {@code xs.sort(null)} is the documented
     *  natural-ordering spelling and {@code Collections.sort(xs, null)} likewise; charging {@code Unknown}
     *  there claims candor cannot rule out an effect that provably cannot occur.
     *
     *  <p>R217 wrote this guard as {@code declType == null}, measured it at 0 rows over 395 jars, found
     *  that no runnable fixture could discriminate it — inside {@code java/util/function/} every invoking
     *  HOF throws on a null argument — and DELETED it rather than ship an untestable narrowing behind a
     *  comment asserting it was safe. Widening the set to {@code Comparator} is what gives it a fixture,
     *  and this is that fixture. It is still 0 rows over the same 395 jars; it is kept because it can now
     *  be made to fail, not because it was measured to matter.
     *
     *  <p>It is {@code ProvValue.nullConst} and NOT {@code declType == null}, which is also null for a
     *  merge of two different declared types and for an array-element read — suppressing on that would go
     *  SILENT on a genuine opaque callback. The {@code maybeNull} row is the control for exactly that:
     *  one arm of the join is a real comparator, so the flag collapses and the site charges.
     *
     *  <p>DISCRIMINATING: deleting {@code if (a.nullConst) return;} reddens {@code naturalOrder} and
     *  {@code collectionsNull}; making the merge take {@code a.nullConst || b.nullConst} reddens
     *  {@code maybeNull}. */
    @Test
    void aProvableNullComparatorIsNotACallback() throws Exception {
        Path cls = compile(Map.of("app/Nat.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "public class Nat {",
            "  public void naturalOrder(List<String> xs) { xs.sort(null); }",
            "  public void collectionsNull(List<String> xs) { Collections.sort(xs, null); }",
            "  public void maybeNull(List<String> xs, Comparator<String> c, boolean f) { xs.sort(f ? c : null); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "app.Nat.naturalOrder").contains(Effect.UNKNOWN),
                "xs.sort(null) is natural ordering: no callback is handed over and none can run. Got "
                + r.get("app.Nat.naturalOrder"));
            assertFalse(eff(r, "app.Nat.collectionsNull").contains(Effect.UNKNOWN),
                "and the Collections spelling of the same fact. Got " + r.get("app.Nat.collectionsNull"));
            assertTrue(eff(r, "app.Nat.maybeNull").contains(Effect.UNKNOWN),
                "THE CONTROL that keeps the guard from being a silent under-report: one arm of the join "
                + "is a real comparator, so `nullConst` must collapse at the merge exactly as every other "
                + "narrowing field on ProvValue does. Got " + r.get("app.Nat.maybeNull"));
        } finally { rm(cls.getParent()); }
    }

    /** A SCANNED IMPLEMENTOR IS RESOLVED, NOT HEDGED. When the project itself implements
     *  {@code Comparator}, the CHA fan-out is non-empty and the unpinned-SAM branch does not fire — the
     *  effect comes from the real body instead of a disclosure. This is why the fixture in
     *  {@link #everyArmChargesTheComparatorFamily} deliberately contains no implementor: an
     *  implementor in scope masks every cell this row is about, which is a measurement trap and not a
     *  hypothetical — it cost a full re-measure while this fix was being built.
     *
     *  <p>DISCRIMINATING: dropping the {@code targets.isEmpty()} gate reddens {@code viaImpl} (it would
     *  gain {@code Unknown} beside the {@code Fs} it already resolves). */
    @Test
    void aScannedComparatorImplementorResolvesThroughCha() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Dirty.java", String.join("\n",
            "package app;",
            "import java.nio.file.*;",
            "import java.util.*;",
            "public class Dirty implements Comparator<String> {",
            "  public int compare(String a, String b) {",
            "    try { Files.writeString(Paths.get(\"/dev/null\"), \"x\"); } catch (Exception e) {}",
            "    return 0; }",
            "}"));
        m.put("app/Use.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "public class Use {",
            "  public int viaImpl(Comparator<String> c) { return c.compare(\"a\", \"b\"); }",
            "}"));
        Path cls = compile(m);
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(eff(r, "app.Use.viaImpl").contains(Effect.FS),
                "the only implementor in scope really writes, and CHA resolves to it — a disclosure here "
                + "would be a hedge on a question the scan can answer exactly. Got " + r.get("app.Use.viaImpl"));
            assertFalse(eff(r, "app.Use.viaImpl").contains(Effect.UNKNOWN),
                "…and it must not ALSO hedge. Got " + r.get("app.Use.viaImpl"));
        } finally { rm(cls.getParent()); }
    }

    /** THE FOUR SPELLINGS OF ONE EXPRESSION AGREE, AND THE CHANNEL IS BYTE-IDENTICAL. The claim R236
     *  makes is parity across the arms, so this pins it instead of asserting it in a comment (§E2). On a
     *  jar built at {@code 9dfd5d2} all four are ABSENT, which is the defect; note in particular that the
     *  LAMBDA spelling was silent too, because a lambda's body is judged by this same branch one frame in
     *  — the R183 comment that reasoned from "{@code (a,b) -> c.compare(a,b)} stays pure" was reading a
     *  hole as a stance. */
    @Test
    void theFourSpellingsAgreeOnTheComparator() throws Exception {
        Path cls = compile(Map.of("app/Spell.java", String.join("\n",
            "package app;",
            "import java.util.*;",
            "public class Spell {",
            "  public void opaqueArm(List<String> xs, Comparator<String> c)  { xs.sort(c); }",
            "  public void referenceArm(List<String> xs, Comparator<String> c) { xs.sort(c::compare); }",
            "  public void lambdaArm(List<String> xs, Comparator<String> c)  { xs.sort((a,b) -> c.compare(a,b)); }",
            "  public int  directArm(Comparator<String> c)                   { return c.compare(\"a\",\"b\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            for (String m : new String[] {"opaqueArm", "referenceArm", "lambdaArm", "directArm"})
                assertTrue(eff(r, "app.Spell." + m).contains(Effect.UNKNOWN),
                    m + " is the same expression in a different spelling and must get the same answer. "
                    + "Got " + r.get("app.Spell." + m));
            assertEquals("[callback:java.util.Comparator.compare]", whyOf("app.Spell.opaqueArm"),
                "the opaque arm's rendered reason");
            assertEquals("[callback:java.util.Comparator.compare]", whyOf("app.Spell.referenceArm"),
                "byte-identical from the creation-site arm, not merely also-non-silent");
            assertEquals("[callback:java.util.Comparator.compare]", whyOf("app.Spell.directArm"),
                "and from the direct invoke");
        } finally { rm(cls.getParent()); }
    }

    /** THE BOUNDARY, MOVED AGAIN — this register was {@code theHofTableBoundaryThisRowDoesNotWiden}, then
     *  {@code theRemainingBoundaryIsTheOPAQUECallbackNotTheSpelling} (R183), then
     *  {@code theRemainingBoundaryIsTheInterfaceSetNotTheOpaqueness} (R217). R236 made THAT boundary
     *  obsolete rather than merely crossing it: opaqueness stopped deciding at R217, and the interface
     *  set stopped deciding here.
     *
     *  <p><b>What the boundary is now: the OWNER LIST.</b> {@code Candor#isFunctionalIface} is a fixed
     *  list — the {@code java/util/function/} package plus six named owners — so a functional interface
     *  outside it is still silent in every arm. {@code ThreadFactory} is the JDK case pinned below;
     *  a dependency's own callback type ({@code IOConsumer}) is the third-party one.
     *
     *  <p><b>Why the obvious widening is NOT the answer.</b> Keying on {@code samNameOf}'s 732-interface
     *  JDK index was built and MEASURED for R183 and charges where the lambda spelling is pure —
     *  {@code map(Iterable::iterator)}, {@code map(Principal::getName)}, {@code map(m::matches)} — because
     *  those SAMs are ordinary classified JDK calls. That is a fabrication on the front door of
     *  {@code Stream}. This residual is the price of not taking it, and it is recorded here rather than
     *  left implicit in a design note.
     *
     *  <p>Pinned exactly as before: when it is closed, this row goes RED and the register moves with it.
     *  {@code covered} is the control that keeps the two questions apart — the same DIRECT invoke on the
     *  same shape of parameter, differing only in the owner. */
    @Test
    void theRemainingBoundaryIsTheOwnerListNotTheInterfaceKind() throws Exception {
        Path cls = compile(Map.of("app/Edge.java", String.join("\n",
            "package app;",
            "import java.util.concurrent.*;",
            "import java.util.function.*;",
            "public class Edge {",
            "  public Thread unlisted(ThreadFactory f) { return f.newThread(() -> {}); }",
            "  public String covered(Supplier<String> s) { return s.get(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertFalse(eff(r, "app.Edge.unlisted").contains(Effect.UNKNOWN),
                "RESIDUAL, NOT A CLAIM OF CORRECTNESS: ThreadFactory.newThread is a caller-supplied "
                + "callback that really runs, and ThreadFactory is a JDK functional interface outside "
                + "`isFunctionalIface`'s owner list, so it is silent. An OPEN silent under-report — the "
                + "one that needs the OWNER list widened without taking the 732-interface index that was "
                + "measured to fabricate. Got " + r.get("app.Edge.unlisted"));
            assertTrue(eff(r, "app.Edge.covered").contains(Effect.UNKNOWN),
                "…and the CONTROL that separates the two: the same direct invoke on the same shape of "
                + "parameter, differing only in the owner. If this went silent the row above would read "
                + "as a boundary when it was really a regression. Got " + r.get("app.Edge.covered"));
        } finally { rm(cls.getParent()); }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    /** The rendered {@code unknownWhy} strings recorded for {@code fn} by the scan just run. */
    private static String whyOf(String fn) {
        TreeSet<UnknownReason> s = AnalysisState.ctx().unknownWhy.get(fn);
        return s == null ? "<none>" : s.toString();
    }
}
