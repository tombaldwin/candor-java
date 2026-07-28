package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * A RAW NUL BYTE IN A SOURCE FILE MAKES THAT FILE INVISIBLE TO `grep`.
 *
 * <p>{@code Policy.unanswerableKey} joined a rule's source line to a function name with a literal NUL
 * written between the quotes rather than the {@code \0} escape. The two are the same string to the
 * compiler and nothing about the engine's behaviour differed — but {@code grep} classifies a file holding
 * a NUL as BINARY and, with no {@code -a}, reports NO MATCHES and exits 1 for it. That silently removed
 * 1,105 lines of the policy parser from every search anyone (or any agent) ran over this tree, and the
 * failure mode is the one that hides itself: a search over the file that contains the answer comes back
 * empty and reads as "not here".
 *
 * <p>Not hypothetical and not local to this engine: candor-ts introduced the identical defect from a
 * template-literal separator in the same session and removed it. The idiom — an unlikely character as a
 * key separator — recurs, so the guard is over the whole main source tree rather than the one line.
 */
class SourceHygieneTest {

    @Test
    void noMainSourceFileHoldsARawNulByte() throws IOException {
        Path root = Path.of("src/main/java");
        assertTrue(Files.isDirectory(root), "the main source tree must be findable from the test's working "
                + "directory, or this guard silently passes over zero files: " + root.toAbsolutePath());
        List<String> offenders = new ArrayList<>();
        int scanned = 0;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                scanned++;
                byte[] b = Files.readAllBytes(p);
                for (byte x : b)
                    if (x == 0) { offenders.add(p.toString()); break; }
            }
        }
        // The control: a guard that walked an empty tree would report success just as loudly.
        assertTrue(scanned > 0, "scanned no .java files at all — the guard proved nothing");
        assertTrue(offenders.isEmpty(), "these source files hold a raw NUL byte, so `grep` treats them as "
                + "BINARY and reports no matches for anything in them — write the `\\0` ESCAPE instead, "
                + "which compiles to the identical string: " + offenders);
    }
}
