package io.poly.candor;

import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * R58 (candor-spec SOUNDNESS.md, macro/codegen row): candor-java reads compiled {@code .class} files
 * only ({@link Loader}), so a Lombok-style processor that rewrites bytecode IN PLACE is immune by
 * construction — the rewritten bytecode IS what gets analysed. But Dagger/Room/AutoValue/MapStruct-style
 * processors emit a SEPARATE {@code .java} file, compiled to its own {@code .class} in the SAME output
 * directory {@link Loader#collectClasses} walks — a different mechanism nothing in {@code Loader.java}
 * special-cases, excludes, or even notices. That was plausible-but-unmeasured until a real
 * {@code dagger-compiler} 2.51.1 build was scanned by hand (scratch fixture, not checked in): a
 * {@code @Provides} method doing a real filesystem write, exposed through a generated
 * {@code AppModule_ProvideLoggerFactory} + {@code DaggerAppComponent$AppComponentImpl}, scanned clean —
 * effects propagated through every generated hop, attributed correctly all the way to the caller, {@code
 * deny Fs} still bit with exit 1 even when the ENTIRE reachable violating path ran through generated
 * code, and a sibling generated method that did NOT reach the effect stayed pure (no blanket
 * over-charge). Verdict: SOUND, not merely unmeasured — the classifier has no annotation-processor
 * concept at all, so ordinary bytecode/call-graph tracing already covers this shape with no special
 * casing needed.
 *
 * <p>This test pins that finding as a standing regression, without a real Dagger dependency: the
 * classifier has no annotation-processor concept, so what matters is the SHAPE dagger-compiler actually
 * emits (confirmed against the real build, not guessed) — a separate class implementing a static
 * factory that calls back into the user's method ({@code get() -> provideX(module) -> module.provide()}),
 * wrapped in a call to an external/uncovered library helper ({@code
 * dagger.internal.Preconditions.checkNotNullFromProvides} in the real build; {@code
 * Objects.requireNonNull} here reproduces the identical "wraps the real call in an uncovered library
 * call" shape without needing that dependency on the test classpath), and a generated component impl
 * exposing it through the user-facing interface. No annotations are used anywhere in the fixture —
 * irrelevant to a classifier that only ever sees compiled bytecode.
 */
class AnnotationProcessorCodegenTest {

    @BeforeEach
    void fresh() {
        Candor.resetState();
    }

    private static final String LOGGER = """
        package gen;
        public class Logger {}
        """;

    // The user-written provider — the ONLY place the real effect lives, exactly as AppModule.provideLogger
    // was in the live Dagger fixture.
    private static final String MODULE = """
        package gen;
        import java.nio.file.Files;
        import java.nio.file.Path;
        public class Module {
            public Logger provide() {
                try {
                    Files.write(Path.of(System.getProperty("java.io.tmpdir"), "candor-apt-codegen-test.log"),
                        "x".getBytes());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                return new Logger();
            }
        }
        """;

    // Mirrors dagger-compiler's generated `AppModule_ProvideLoggerFactory`: get() -> provideX(module) ->
    // module.provide(), the real call wrapped in a call to an external/uncovered helper.
    private static final String FACTORY = """
        package gen;
        import java.util.Objects;
        public final class Module_ProvideFactory {
            private final Module module;
            public Module_ProvideFactory(Module module) { this.module = module; }
            public Logger get() { return provide(module); }
            public static Logger provide(Module instance) { return Objects.requireNonNull(instance.provide()); }
        }
        """;

    private static final String COMPONENT = """
        package gen;
        public interface Component { Logger logger(); }
        """;

    // Mirrors dagger-compiler's generated `DaggerAppComponent$AppComponentImpl`. `create()` is the
    // over-charge control: a generated method that never reaches the effect, sitting right beside one that
    // does.
    private static final String COMPONENT_IMPL = """
        package gen;
        public final class GeneratedComponentImpl implements Component {
            private final Module module;
            public GeneratedComponentImpl(Module module) { this.module = module; }
            @Override public Logger logger() { return Module_ProvideFactory.provide(module); }
            public static GeneratedComponentImpl create() { return new GeneratedComponentImpl(new Module()); }
        }
        """;

    // The user's own calling code — dispatches through the `Component` INTERFACE, exactly as every real
    // Dagger caller does (`@Component interface AppComponent`), never the generated impl type directly.
    private static final String APP = """
        package gen;
        public class App {
            public static Logger entry() {
                Component c = GeneratedComponentImpl.create();
                return c.logger();
            }
        }
        """;

    private static Path compileFixture() throws Exception {
        return TestCompiler.compile(Map.of(
            "gen/Logger.java", LOGGER,
            "gen/Module.java", MODULE,
            "gen/Module_ProvideFactory.java", FACTORY,
            "gen/Component.java", COMPONENT,
            "gen/GeneratedComponentImpl.java", COMPONENT_IMPL,
            "gen/App.java", APP));
    }

    private static boolean fs(Map<String, EffectSet> m, String fn) {
        return m.getOrDefault(fn, EffectSet.empty()).toNames().contains("Fs");
    }

    @Test
    void generatedFactoryChainPropagatesTheEffectToTheCaller() throws Exception {
        Path dir = compileFixture();
        try {
            Map<String, EffectSet> inferred = Candor.runScan(dir);
            assertTrue(fs(inferred, "gen.Module.provide"), "the user-written provider method must carry Fs");
            assertTrue(fs(inferred, "gen.Module_ProvideFactory.get"), "generated factory get() must inherit Fs");
            assertTrue(fs(inferred, "gen.Module_ProvideFactory.provide"),
                "generated factory provide() must inherit Fs");
            assertTrue(fs(inferred, "gen.GeneratedComponentImpl.logger"),
                "generated component impl must inherit Fs");
            assertTrue(fs(inferred, "gen.App.entry"), "the effect must reach the user's own calling code");
            // the over-charge control: a generated method that does NOT reach the effect must stay pure —
            // proves the propagation above is call-graph precision, not a blanket "touches generated code"
            // charge.
            assertFalse(fs(inferred, "gen.GeneratedComponentImpl.create"),
                "a generated method not on the effectful path must not be charged Fs");
        } finally {
            TestCompiler.rm(dir.getParent());
        }
    }

    @Test
    void denyFsBitesWhenTheOnlyReachablePathIsEntirelyBehindGeneratedCode() throws Exception {
        Path dir = compileFixture();
        try {
            Map<String, EffectSet> inferred = Candor.runScan(dir);
            Path pol = Files.createTempFile("candor-apt-codegen-policy", ".policy");
            try {
                Files.writeString(pol, "deny Fs\n");
                assertTrue(Policy.checkPolicy(inferred, pol.toString()) > 0,
                    "deny Fs must bite even though the entire violating path runs through generated code");
            } finally {
                Files.deleteIfExists(pol);
            }
        } finally {
            TestCompiler.rm(dir.getParent());
        }
    }
}
