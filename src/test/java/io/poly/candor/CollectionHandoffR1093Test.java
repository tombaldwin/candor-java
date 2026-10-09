package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static io.poly.candor.TestCompiler.compile;
import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1093 — {@code ExecutorService.invokeAll/invokeAny(Collection)} and {@code ForkJoinTask.adapt(task)} hand
 * tasks to an executor exactly as {@code submit(task)} does, and with an OPAQUE task (collection) all three read PURE
 * on v0.40.3 while {@code submit} disclosed. EXECUTED (JDK 21): every task wrote its file; {@code deny Fs} and
 * {@code deny Unknown} exited 0 on each. Controls: {@code submit} (already disclosed), and a lambda handed to
 * {@code adapt}, which is edged at its creation site and so adds no {@code Unknown}.
 */
class CollectionHandoffR1093Test {

    static final String SRC = "package r1093;\nimport java.util.*;\nimport java.util.concurrent.*;\n"
            + "public class H {\n"
            + "  public static void viaInvokeAll(ExecutorService es, Collection<Callable<String>> t) throws Exception { es.invokeAll(t); }\n"
            + "  public static void viaInvokeAny(ExecutorService es, Collection<Callable<String>> t) throws Exception { es.invokeAny(t); }\n"
            + "  public static void viaInvokeAllNull(ExecutorService es) throws Exception { es.invokeAll(null); }\n"
            + "  public static void viaSubmit(ExecutorService es, Callable<String> t) throws Exception { es.submit(t); }\n"
            + "  public static void viaAdapt(Runnable r) { ForkJoinPool.commonPool().invoke(ForkJoinTask.adapt(r)); }\n"
            + "  public static void viaAdaptCallable(Callable<String> c) { ForkJoinPool.commonPool().invoke(ForkJoinTask.adapt(c)); }\n"
            + "  public static void viaAdaptLambda() { ForkJoinPool.commonPool().invoke(ForkJoinTask.adapt(() -> {})); }\n"
            + "}\n";

    static boolean unknown(Map<String, EffectSet> r, String fn) {
        EffectSet e = r.get(fn);
        return e != null && e.effects().stream().anyMatch(x -> x.name().equals("UNKNOWN"));
    }

    @Test
    void opaqueTaskCollectionsAndAdaptedTasksDisclose() throws Exception {
        Path cls = compile(Map.of("r1093/H.java", SRC));
        Config saved = Candor.config;
        try {
            Candor.config = Config.empty();
            Map<String, EffectSet> r = Candor.runScan(cls);
            assertTrue(unknown(r, "r1093.H.viaSubmit"), "CONTROL: submit(task) already disclosed");
            assertTrue(unknown(r, "r1093.H.viaInvokeAll"), "invokeAll(opaque tasks) runs them");
            assertTrue(unknown(r, "r1093.H.viaInvokeAny"), "invokeAny(opaque tasks) runs them");
            assertTrue(unknown(r, "r1093.H.viaAdapt"), "adapt(opaque runnable) is run by pool.invoke");
            assertTrue(unknown(r, "r1093.H.viaAdaptCallable"), "adapt(opaque callable) is run by pool.invoke");
            assertFalse(unknown(r, "r1093.H.viaAdaptLambda"), "a lambda is edged at its creation site — no Unknown");
            assertFalse(unknown(r, "r1093.H.viaInvokeAllNull"), "a provable null hands over no task");
        } finally {
            Candor.config = saved;
            rm(cls.getParent());
        }
    }
}
