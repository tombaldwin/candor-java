package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * R274/R248/R258 — THE SLOT-vs-VALUE OPERAND-STACK INDEX.
 *
 * <p>ASM's {@code Frame} STACK holds ONE ENTRY PER VALUE; {@code Type.getSize()} counts a long/double as
 * two. Nine helpers across {@code Candor}, {@code Interp} and {@code Cha} summed sizes to index the stack,
 * so a category-2 operand made every one of them read BELOW the value it wanted. All now share one
 * authority, {@link Candor#argValueIndex} / {@link Candor#receiverValueIndex}.
 *
 * <p><b>Every fixture here carries a category-2 operand and a category-1 CONTROL of the identical shape</b>,
 * because the whole defect is invisible without that contrast: the pre-fix engine is correct on the control
 * and wrong beside it. Each red assertion below was verified RED against a jar built from the {@code
 * v0.35.0} tag, and each was verified RED again with only the {@code src/main} change stashed.
 *
 * <p><b>Why the pre-existing suite could not see this.</b> {@code StructuralDispatchTest}'s
 * {@code timer.schedule(tt, 0L)} line — its ONE long-bearing hand-off — passes on the BROKEN engine,
 * because a single category-2 argument after the task makes {@code handoffTaskArg} return the RECEIVER, and
 * that fixture's receiver is an opaque PARAM, which is independently Unknown-worthy. The assertion was green
 * on a fabricated reason. {@link #handoffTaskIsReadByValueNotBySlot} therefore varies the RECEIVER's
 * provenance as an explicit axis, and {@link #noFabricatedUnknownOnAVisibleTask} pins the other direction.
 */
class StackValueIndexTest {

    @TempDir
    Path tmp;

    @BeforeEach
    void reset() {
        Candor.resetState();
    }

    @AfterEach
    void restore() {
        Candor.config = Config.empty();
    }

    private static Map<String, EffectSet> scan(Map<String, String> sources) throws Exception {
        Path out = TestCompiler.compile(sources);
        try {
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }

    // ── 1. handoffTaskArg — arg0 of the scheduling surface (R248, PUBLISHED in 0.34.0 + 0.35.0) ───────

    /**
     * The whole grid: {0,1,2} category-2 args AFTER the task × {a `new` receiver, an opaque field receiver}.
     * With the size-sum, ONE trailing long returned the RECEIVER (silent when that receiver is a provable
     * `new`, incidentally right when it is opaque) and TWO drove the index negative and returned null
     * (silent either way). Ground truth: every one of these tasks really runs.
     */
    @Test
    void handoffTaskIsReadByValueNotBySlot() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("app/H.java", """
                package app;
                import java.util.*;
                import java.util.concurrent.*;
                public class H {
                  TimerTask tt; Runnable task;                 // OPAQUE — no body candor can see
                  Timer timerField; ScheduledExecutorService esField;

                  // n2 = 0 — correct even with the size-sum (the controls).
                  void ctlDateNew()   { new Timer(true).schedule(tt, new Date()); }
                  void ctlDateField() { timerField.schedule(tt, new Date()); }

                  // n2 = 1 — the size-sum returned the RECEIVER.
                  void oneNew()       { new Timer(true).schedule(tt, 1L); }
                  void oneField()     { timerField.schedule(tt, 1L); }
                  void oneDateNew()   { new Timer(true).schedule(tt, new Date(), 100000L); }
                  void oneSchedNew()  { new ScheduledThreadPoolExecutor(1)
                                          .schedule(task, 1L, TimeUnit.MILLISECONDS); }

                  // n2 = 2 — the size-sum drove the index NEGATIVE and returned null.
                  void twoNew()       { new Timer(true).schedule(tt, 1L, 100000L); }
                  void twoField()     { timerField.schedule(tt, 1L, 100000L); }
                  void twoRateField() { timerField.scheduleAtFixedRate(tt, 1L, 100000L); }
                  void twoRateSched() { esField.scheduleAtFixedRate(task, 1L, 100000L,
                                          TimeUnit.MILLISECONDS); }
                  void twoDelaySched(){ esField.scheduleWithFixedDelay(task, 1L, 100000L,
                                          TimeUnit.MILLISECONDS); }
                }
                """));
        for (String fn : new String[] {"ctlDateNew", "ctlDateField", "oneNew", "oneField", "oneDateNew",
                "oneSchedNew", "twoNew", "twoField", "twoRateField", "twoRateSched", "twoDelaySched"})
            assertTrue(eff(r, "app.H." + fn).toNames().contains("Unknown"),
                    "an OPAQUE task handed to a scheduler must read Unknown, got "
                            + eff(r, "app.H." + fn) + " for app.H." + fn);
    }

    /**
     * The OTHER direction of the same arithmetic, and half the argument for one authority: with the
     * size-sum, {@code timerField.schedule(new VisibleTask(), 1L)} read the opaque FIELD receiver as if it
     * were the task and charged a {@code task-handoff} Unknown against a provably-pure program. Four such
     * cells were measured fabricating. The task here is a project class with an EMPTY body.
     */
    @Test
    void noFabricatedUnknownOnAVisibleTask() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("app/V.java", """
                package app;
                import java.util.*;
                import java.util.concurrent.*;
                public class V {
                  static class Quiet extends TimerTask { public void run() { } }
                  static class QuietR implements Runnable { public void run() { } }
                  Timer timerField; ScheduledExecutorService esField;
                  void oneField()    { timerField.schedule(new Quiet(), 1L); }
                  void oneDateField(){ timerField.scheduleAtFixedRate(new Quiet(), new Date(), 100000L); }
                  void oneSched()    { esField.schedule(new QuietR(), 1L, TimeUnit.MILLISECONDS); }
                }
                """));
        for (String fn : new String[] {"oneField", "oneDateField", "oneSched"})
            assertFalse(eff(r, "app.V." + fn).toNames().contains("Unknown"),
                    "a VISIBLE empty-bodied task must NOT be charged Unknown off the receiver, got "
                            + eff(r, "app.V." + fn) + " for app.V." + fn);
    }

    // ── 2. receiverProv — the abstract-stream receiver (R258 + R17) ───────────────────────────────────

    /**
     * {@code isAbstractStreamIo}'s verb list is {@code read*}/{@code write*}/{@code skip*}/{@code
     * transferTo}/{@code append}; the JDK spells exactly three of them with a long — {@code
     * InputStream.skip}, {@code InputStream.skipNBytes}, {@code Reader.skip} — and those three were the
     * ones {@code receiverProv} could not locate (stack size 2, size-sum 2, index -1 → null → silent).
     */
    @Test
    void storedStreamReceiverIsReadByValueNotBySlot() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("app/S.java", """
                package app;
                import java.io.*;
                public class S {
                  static InputStream in; static Reader rd;
                  static void open() throws Exception {
                    in = new FileInputStream("d"); rd = new FileReader("d");
                  }
                  static int  ctlRead()      throws Exception { return in.read(); }          // control
                  static int  ctlRead3()     throws Exception { return in.read(new byte[4], 0, 2); }
                  static long skip()         throws Exception { return in.skip(2L); }
                  static void skipNBytes()   throws Exception { in.skipNBytes(2L); }
                  static long readerSkip()   throws Exception { return rd.skip(2L); }
                }
                """));
        for (String fn : new String[] {"ctlRead", "ctlRead3", "skip", "skipNBytes", "readerSkip"})
            assertTrue(eff(r, "app.S." + fn).toNames().contains("Fs"),
                    "a read through a stored stream handle must carry the acquisition's Fs, got "
                            + eff(r, "app.S." + fn) + " for app.S." + fn);
    }

    /** R17's {@code entryAbstractStream} shares {@code receiverProv} and shared the hole: an entry point
     *  reading its own framework-injected stream param via {@code skip(long)} disclosed NOTHING, while every
     *  category-1 verb of the same predicate disclosed Unknown. */
    @Test
    void entryPointStreamParamReceiverIsReadByValueNotBySlot() throws Exception {
        Map<String, EffectSet> r = scan(Map.of(
                "jakarta/servlet/http/HttpServlet.java",
                "package jakarta.servlet.http;\npublic class HttpServlet { }\n",
                "app/E.java", """
                package app;
                import java.io.*;
                public class E extends jakarta.servlet.http.HttpServlet {
                  public int  doGet(InputStream h)   throws Exception { return h.read(); }
                  public long service(InputStream h)    throws Exception { return h.skip(2L); }
                }
                """));
        assertTrue(eff(r, "app.E.doGet").toNames().contains("Unknown"),
                "control (a category-1 verb on the same rooted entry point) must be Unknown, got "
                        + eff(r, "app.E.doGet"));
        assertTrue(eff(r, "app.E.service").toNames().contains("Unknown"),
                "an entry point skipping bytes on its own stream param must read Unknown, got "
                        + eff(r, "app.E.service"));
    }

    // ── 3. monomorphicReceiver — the CHA switch (R274; the widest of the three) ───────────────────────

    /**
     * The worst of the sites: a non-null {@code monoRecv} switches OFF the CHA over-approximation. With the
     * size-sum, {@code new StringBuilder().append(h.work(1L))} read the StringBuilder as {@code h}'s
     * receiver, so the interface call resolved to nothing, edged to nothing and disclosed nothing —
     * executed silent-pure over a real file write, on an UNBOUNDED surface (any virtual/interface call whose
     * descriptor carries a long/double, with any value beneath the receiver on the stack).
     */
    @Test
    void monomorphicReceiverIsReadByValueNotBySlot() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("app/M.java", """
                package app;
                public class M {
                  public interface W { String workL(long n); String workI(int n); }
                  public static class Dirty implements W {
                    public String workL(long n) { return io(); }
                    public String workI(int n)  { return io(); }
                    private String io() {
                      try { return new java.io.File("x").getCanonicalPath(); }
                      catch (Exception e) { return ""; }
                    }
                  }
                  static W h;
                  // control: category-1 arg, a `new` below the receiver — resolved, Fs.
                  static void ctlIntBelow()  { new StringBuilder().append(h.workI(1)); }
                  // control: category-2 arg, NOTHING below the receiver — index goes negative, CHA runs.
                  static void ctlLongAlone() { h.workL(1L); }
                  // the defect: category-2 arg AND a `new` below the receiver.
                  static void longBelow()    { new StringBuilder().append(h.workL(1L)); }
                }
                """));
        for (String fn : new String[] {"ctlIntBelow", "ctlLongAlone", "longBelow"})
            assertTrue(eff(r, "app.M." + fn).toNames().contains("Fs"),
                    "the CHA edge to Dirty.work must survive a category-2 argument, got "
                            + eff(r, "app.M." + fn) + " for app.M." + fn);
    }

    // ── 4. fieldBoundImplementors (Cha) — MEASURED NON-SILENT; folded in as precision ─────────────────

    /**
     * The pre-fix fail direction here was measured and it is NOT the cardinal sin: a SAM carrying a long
     * lost the field's lambda binding and fell back to the pre-existing CHA/Unknown path, disclosing
     * {@code Unknown}/{@code dispatch:app.F.W.w}. This asserts the PRECISION the one-authority fix buys —
     * the binding survives — so a future reader does not inherit the "fails silently" claim.
     */
    @Test
    void fieldBoundImplementorReceiverIsReadByValueNotBySlot() throws Exception {
        Map<String, EffectSet> r = scan(Map.of("app/F.java", """
                package app;
                public class F {
                  public interface W { void w(long n); }
                  static W h;
                  static { h = n -> { try { new java.io.FileInputStream("x").close(); }
                                      catch (Exception e) { } }; }
                  static void go() { h.w(1L); }
                }
                """));
        assertTrue(eff(r, "app.F.go").toNames().contains("Fs"),
                "the field's lambda binding must survive a category-2 SAM argument, got "
                        + eff(r, "app.F.go"));
        assertFalse(eff(r, "app.F.go").toNames().contains("Unknown"),
                "a fully-bound field lambda must not degrade to Unknown, got " + eff(r, "app.F.go"));
    }

    // ── 5. argsTainted (Interp) — the AS-EFF-007 advisory, fabrication direction ──────────────────────

    /**
     * {@code argsTainted} asks "is any ARGUMENT (NOT the receiver) tainted?". Walking the top
     * {@code Sum(getSize())} entries made it read PAST the argument block into the receiver, so
     * {@code in.skip(2L)} — whose only argument is the constant {@code 2L} — was flagged as an injection
     * surface off its tainted RECEIVER. The category-1 control beside it was not.
     */
    @Test
    void taintReadsArgumentsNotTheReceiver() throws Exception {
        Path cfg = Files.createTempFile(tmp, "cfg", "");
        Files.writeString(cfg, "taint true\n");
        Candor.config = Config.load(cfg);
        Path out = TestCompiler.compile(Map.of("app/T.java", """
                package app;
                import java.io.*;
                public class T {
                  public static long skipArm(FileInputStream in) throws Exception { return in.skip(2L); }
                  public static int  readArm(FileInputStream in) throws Exception {
                    return in.read(new byte[4], 0, 2);
                  }
                }
                """));
        try {
            Candor.runScan(out);
            assertEquals(EffectSet.empty(), AnalysisState.ctx().tainted
                            .getOrDefault("app.T.readArm", EffectSet.empty()),
                    "control: no category-2 argument, no argument tainted");
            assertEquals(EffectSet.empty(), AnalysisState.ctx().tainted
                            .getOrDefault("app.T.skipArm", EffectSet.empty()),
                    "skip(2L)'s only argument is a constant — the tainted RECEIVER must not be read as one");
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    // ── 6. the authority itself — the arithmetic, stated as a table ───────────────────────────────────

    /** The frame STACK is indexed in VALUES: {@code (Runnable,long,long,TimeUnit)} occupies FOUR entries,
     *  not six, and its receiver sits one below all four. The pre-fix arithmetic put arg0 at {@code
     *  stackSize-6} — two below the bottom of a five-deep stack. */
    @Test
    void theAuthorityCountsValuesNotSlots() {
        org.objectweb.asm.Type[] at = org.objectweb.asm.Type.getArgumentTypes(
                "(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;");
        assertEquals(4, at.length, "four DECLARED arguments");
        int stack = 5; // receiver + four argument VALUES
        assertEquals(1, Candor.argValueIndex(stack, at, 0), "arg0 (the task)");
        assertEquals(2, Candor.argValueIndex(stack, at, 1), "arg1 (a long — ONE entry)");
        assertEquals(4, Candor.argValueIndex(stack, at, 3), "arg3 (the TimeUnit)");
        assertEquals(0, Candor.receiverValueIndex(stack, at), "the receiver, below all four");
        assertEquals(-1, Candor.argValueIndex(stack, at, 4), "out of range");
        assertEquals(-1, Candor.argValueIndex(stack, at, -1), "out of range");
        assertEquals(-1, Candor.receiverValueIndex(4, at), "a static call has no receiver entry");
    }
}
