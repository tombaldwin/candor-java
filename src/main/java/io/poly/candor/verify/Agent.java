package io.poly.candor.verify;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/**
 * ⟨verify⟩ The java.lang.instrument agent entry point of the JVM honesty oracle. The SAME shadowJar that is
 * the candor CLI is also this agent (build.gradle.kts adds {@code Premain-Class}); {@code candor-java verify}
 * injects it via {@code -javaagent:<thisJar>=<includeFile>} through JAVA_TOOL_OPTIONS, so it attaches to every
 * JVM the target's {@code --run} command spawns (including gradle test workers).
 *
 * <p>{@code agentArgs} is the path to a file listing the INCLUDE dotted class names (one per line, written by
 * the CLI from the report's functions). We read them into a set and register the {@link EffectTransformer}.
 * The target's own classes load AFTER premain, so a transformer registered here sees them on first load — no
 * retransform of already-loaded classes is needed (and we skip it for simplicity).
 */
public final class Agent {

    private Agent() {}

    public static void premain(String agentArgs, Instrumentation inst) {
        Set<String> include = new HashSet<>();
        if (agentArgs != null && !agentArgs.isEmpty()) {
            try {
                for (String line : Files.readAllLines(Path.of(agentArgs))) {
                    String c = line.trim();
                    if (!c.isEmpty()) include.add(c);
                }
            } catch (IOException e) {
                // No include file → nothing to instrument. The oracle then witnesses zero effects and
                // reports a vacuous HOLD (disclosed by the executed-fn count) rather than crashing the app.
                System.err.println("candor verify agent: cannot read include file " + agentArgs + ": " + e.getMessage());
            }
        }
        inst.addTransformer(new EffectTransformer(include), true /* canRetransform */);
    }
}
