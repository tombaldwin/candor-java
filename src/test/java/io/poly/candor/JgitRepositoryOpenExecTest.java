package io.poly.candor;

import io.poly.candor.model.Effect;
import io.poly.candor.model.EffectSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R498 — {@code org.eclipse.jgit.api.Git.open(File)} answered {@code Fs} while the call reaches
 * a real {@code new java.lang.ProcessBuilder(String[]).start()}.
 *
 * <p>This is the [[R494]]/[[R496]] WEAKER-CLAIM class, not an absence: {@code Fs} is a positive, entirely
 * plausible answer for "open a repository", and it satisfies every disclosure channel the engine has, so
 * nothing anywhere said the {@code Exec} was missing.
 *
 * <p><b>MEASURED PRE-FIX on a CONSUMER COMPILED AGAINST THE REAL JAR</b> (org.eclipse.jgit-6.10.0, library
 * OUT of scope — the shape these rules exist for). {@code App.openRepo} reported {@code inferred: ["Fs"]}
 * and {@code deny Exec} / {@code deny Exec Unknown} BOTH exited 0. Post-fix it is {@code ["Exec","Fs"]}
 * and both exit 1. Calibration on the same tree with the same jar and the same policy file: a sibling
 * method doing {@code new ProcessBuilder("id").start()} reddened {@code deny Exec} pre-fix as well as
 * post, so the pre-fix exit 0 was an under-report and not a broken scan.
 *
 * <p><b>RUNTIME PROOF, not only {@code javap}.</b> The same consumer run with a logging {@code git} shim
 * first on PATH forks TWICE from that one call: {@code git --version} and
 * {@code git config --system --show-origin --list -z}. Run with NO {@code git} on PATH at all it forks
 * {@code bash --login -c "which git"} instead. <b>Which arm fires is decided by the machine's PATH, never
 * by anything in the caller's code</b> — precisely the input candor cannot see — which is why the sound
 * answer is disclosure, exactly as [[R496]] settled for the AWS credential chain.
 *
 * <p><b>The under-report was DISCLOSED, not silent, and that is what fixes the severity below a cardinal
 * sin.</b> {@code org.eclipse} is NOT in {@code Rules.KAPPA_COVERED_PREFIXES} — measured, not read off the
 * list: the pre-fix report carried {@code invisible: ["org.eclipse.jgit.api"]} plus the coverage advisory
 * alongside the {@code Fs}. It was still a gate PASS over a real fork, which is what this pins. The same
 * measurement is why the fix is an ENUMERATION rather than [[R480]]'s whole-type-plus-denylist: a jgit
 * member the predicate misses keeps that honest {@code invisible} floor instead of becoming a purity
 * claim, so the condition R480's mandate depends on does not hold here.
 *
 * <p>Stubs below carry the REAL signatures, read off {@code javap -p} of the 6.10.0 jar rather than
 * guessed — {@code Git.open} takes a {@code File} and there is no {@code Path} overload in any published
 * release, so the descriptor gate's {@code Path} arm is asserted at the table only.
 */
class JgitRepositoryOpenExecTest {

    // ── the stub library (compiled to a separate -classpath dir, never scanned) ─────────────────────

    private static final Map<String, String> LIB = Map.ofEntries(
        Map.entry("org/eclipse/jgit/util/FS.java",
            String.join("\n",
            "package org.eclipse.jgit.util;",
            "import java.io.File;",
            "public abstract class FS {",
            "  public static final FS DETECTED = null;",
            "  public static FS detect() { return null; }",
            "  public File getGitSystemConfig() { return null; }",
            "  public int runProcess(ProcessBuilder pb, Object o, Object e, String in) { return 0; }",
            "  public abstract ProcessBuilder runInShell(String cmd, String[] args);",
            "  public Object execute(ProcessBuilder pb, java.io.InputStream in) { return null; }",
            "  public Object runHookIfPresent(Object repo, String name, String[] args) { return null; }",
            "  public File resolve(File dir, String name) { return null; }",
            "  public boolean isCaseSensitive() { return true; }",
            "}")),
        Map.entry("org/eclipse/jgit/util/SystemReader.java",
            String.join("\n",
            "package org.eclipse.jgit.util;",
            "public abstract class SystemReader {",
            "  public static SystemReader getInstance() { return null; }",
            "  public Object getUserConfig() { return null; }",
            "  public Object getSystemConfig() { return null; }",
            "  public String getenv(String v) { return null; }",
            "  public String getHostname() { return null; }",
            "}")),
        Map.entry("org/eclipse/jgit/lib/Repository.java",
            "package org.eclipse.jgit.lib;\npublic abstract class Repository implements AutoCloseable {"
                + " public void close() {} public String getBranch() { return null; } }"),
        Map.entry("org/eclipse/jgit/lib/ObjectId.java",
            "package org.eclipse.jgit.lib;\npublic class ObjectId {"
                + " public static ObjectId fromString(String s) { return null; }"
                + " public String name() { return null; } }"),
        Map.entry("org/eclipse/jgit/lib/BaseRepositoryBuilder.java",
            String.join("\n",
            "package org.eclipse.jgit.lib;",
            "import java.io.File;",
            "public class BaseRepositoryBuilder {",
            "  public BaseRepositoryBuilder setGitDir(File d) { return this; }",
            "  public BaseRepositoryBuilder readEnvironment() { return this; }",
            "  public File getGitDir() { return null; }",
            "  public BaseRepositoryBuilder setup() { return this; }",
            "  public Repository build() { return null; }",
            "}")),
        Map.entry("org/eclipse/jgit/storage/file/FileRepositoryBuilder.java",
            "package org.eclipse.jgit.storage.file;\nimport org.eclipse.jgit.lib.BaseRepositoryBuilder;\n"
                + "public class FileRepositoryBuilder extends BaseRepositoryBuilder {}"),
        Map.entry("org/eclipse/jgit/lib/RepositoryCache.java",
            "package org.eclipse.jgit.lib;\nimport java.io.File;\npublic class RepositoryCache {"
                + " public static Repository open(File key) { return null; }"
                + " public static void clear() {} }"),
        Map.entry("org/eclipse/jgit/api/InitCommand.java",
            "package org.eclipse.jgit.api;\nimport java.io.File;\npublic class InitCommand {"
                + " public InitCommand setDirectory(File d) { return this; } public Git call() { return null; } }"),
        Map.entry("org/eclipse/jgit/api/CommitCommand.java",
            "package org.eclipse.jgit.api;\npublic class CommitCommand {"
                + " public CommitCommand setMessage(String m) { return this; }"
                + " public Object call() { return null; } }"),
        Map.entry("org/eclipse/jgit/api/AddCommand.java",
            "package org.eclipse.jgit.api;\npublic class AddCommand {"
                + " public AddCommand addFilepattern(String p) { return this; }"
                + " public Object call() { return null; } }"),
        Map.entry("org/eclipse/jgit/hooks/PreCommitHook.java",
            "package org.eclipse.jgit.hooks;\npublic class PreCommitHook { public Void call() { return null; } }"),
        Map.entry("org/eclipse/jgit/api/Git.java",
            String.join("\n",
            "package org.eclipse.jgit.api;",
            "import java.io.File;",
            "import org.eclipse.jgit.lib.Repository;",
            "public class Git implements AutoCloseable {",
            "  public static Git open(File dir) { return null; }",
            "  public static Git wrap(Repository r) { return null; }",
            "  public static InitCommand init() { return null; }",
            "  public CommitCommand commit() { return null; }",
            "  public AddCommand add() { return null; }",
            "  public void close() {}",
            "}")));

    // ── the gap fixture ────────────────────────────────────────────────────────────────────────────

    /** The row's own call, and the sibling spellings of "give me a Repository" that reach the same fork.
     *  All five were {@code Exec}-free pre-fix; {@code openRepo} carried the misleading {@code Fs} alone. */
    @Test
    void openingAGitRepositoryIsExecAsWellAsFs() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Repo.java", String.join("\n",
            "package com.x;",
            "import org.eclipse.jgit.api.Git;",
            "import org.eclipse.jgit.lib.RepositoryCache;",
            "import org.eclipse.jgit.storage.file.FileRepositoryBuilder;",
            "import org.eclipse.jgit.util.SystemReader;",
            "import java.io.File;",
            "public class Repo {",
            "  public Git openRepo(String p) { return Git.open(new File(p)); }",
            "  public Object viaBuilder(String p) { return new FileRepositoryBuilder().setGitDir(new File(p)).build(); }",
            "  public Object viaCache(String p) { return RepositoryCache.open(new File(p)); }",
            "  public Object viaInit(String p) { return Git.init().setDirectory(new File(p)).call(); }",
            "  public Object viaSystemReader() { return SystemReader.getInstance().getUserConfig(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"openRepo", "viaBuilder", "viaCache", "viaInit", "viaSystemReader"}) {
                assertTrue(eff(r, "com.x.Repo." + m).contains(Effect.EXEC),
                    m + " materialises a repository, which forks `git` — must be Exec, got " + r.get("com.x.Repo." + m));
            }
            // THE Fs IS NOT DISPLACED. `classify` returns one effect, so the whole fix is a co-emission;
            // if the Exec ever arrived by REPLACING the Fs this would be a sideways move, not a fix, and
            // a `deny Fs` gate over a repository read would start passing.
            for (String m : new String[] {"openRepo", "viaBuilder", "viaCache", "viaInit"}) {
                assertTrue(eff(r, "com.x.Repo." + m).contains(Effect.FS),
                    m + " also reads .git/config off disk — the Fs must survive, got " + r.get("com.x.Repo." + m));
            }
        } finally { rm(app.getParent()); }
    }

    /** JGit's own subprocess surface — the members {@code readPipe} funnels through. {@code runInShell}
     *  is the payload CARRIER ([[R480]]'s shape: it hands back an armed {@code ProcessBuilder} for someone
     *  else to launch), and reading a hook's result is the capability {@code Process.getInputStream} is
     *  charged for. Note {@code getGitSystemConfig} is NOT Fs-only despite its name and return type. */
    @Test
    void jgitsOwnSubprocessSurfaceIsExec() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Fs.java", String.join("\n",
            "package com.x;",
            "import org.eclipse.jgit.util.FS;",
            "public class Fs {",
            "  public Object sysConfig(FS fs) { return fs.getGitSystemConfig(); }",
            "  public Object shell(FS fs, String c, String[] a) { return fs.runInShell(c, a); }",
            "  public int run(FS fs, ProcessBuilder pb) throws Exception { return fs.runProcess(pb, null, null, \"\"); }",
            "  public Object exec(FS fs, ProcessBuilder pb) { return fs.execute(pb, null); }",
            "  public Object hook(FS fs, Object repo, String[] a) { return fs.runHookIfPresent(repo, \"pre-commit\", a); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"sysConfig", "shell", "run", "exec", "hook"}) {
                assertTrue(eff(r, "com.x.Fs." + m).contains(Effect.EXEC),
                    m + " is on jgit's fork path — must be Exec, got " + r.get("com.x.Fs." + m));
            }
        } finally { rm(app.getParent()); }
    }

    /** THE SECOND MECHANISM, found by sweeping the class rather than stopping at the entry point the row
     *  was filed from: a jgit commit runs the REPOSITORY'S OWN {@code .git/hooks/*} scripts — arbitrary
     *  code the caller never wrote. MEASURED: a consumer doing {@code Git.init()…call(); add(); commit()
     *  .setMessage(m).call()} against a repository carrying an executable {@code .git/hooks/pre-commit}
     *  recorded the hook RUNNING. Whether a hook file exists is a property of the repository on disk,
     *  never of the caller's code — the same argument as the PATH arms, and the same answer.
     *
     *  <p>The CONTROL in the same fixture is what keeps this honest: {@code add().call()} touches the
     *  index and runs no hook, so it must stay {@code Exec}-free even though it is the same
     *  {@code call()} verb on the same {@code Git} handle one command over. */
    @Test
    void committingRunsTheRepositorysHooksAndIsExec() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Hooked.java", String.join("\n",
            "package com.x;",
            "import org.eclipse.jgit.api.Git;",
            "public class Hooked {",
            "  public Object commit(Git g) { return g.commit().setMessage(\"m\").call(); }",
            "  public Object hook(org.eclipse.jgit.hooks.PreCommitHook h) { return h.call(); }",
            "  public Object stage(Git g) { return g.add().addFilepattern(\"f\").call(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"commit", "hook"}) {
                assertTrue(eff(r, "com.x.Hooked." + m).contains(Effect.EXEC),
                    m + " runs the repository's own hook scripts — must be Exec, got " + r.get("com.x.Hooked." + m));
            }
            assertTrue(eff(r, "com.x.Hooked.commit").contains(Effect.FS),
                "a commit also writes the index/objects/refs — the Fs must ride too, got "
                    + r.get("com.x.Hooked.commit"));
            assertFalse(eff(r, "com.x.Hooked.stage").contains(Effect.EXEC),
                "`add().call()` runs no hook — the same verb one command over must NOT gain Exec, got "
                    + r.get("com.x.Hooked.stage"));
        } finally { rm(app.getParent()); }
    }

    // ── OVER-CHARGE CONTROLS ───────────────────────────────────────────────────────────────────────

    /** The widening is owner+verb scoped, and these are the members it must NOT reach. {@code FS.detect()}
     *  selects the platform implementation and forks nothing — {@code javap} shows only
     *  {@code FS$FSFactory.detect}, and a consumer touching {@code FS.detect()} and {@code FS.DETECTED}
     *  recorded ZERO forks on both PATH arms. The rest are jgit's pure value and path surface, which a
     *  whole-package {@code Exec} would have swallowed. Executed end-to-end rather than asserted at the
     *  table, because an absence-shaped control is only evidence if the program reaches the branch. */
    @Test
    void control_jgitsPureSurfaceGainsNothing() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Pure.java", String.join("\n",
            "package com.x;",
            "import org.eclipse.jgit.util.FS;",
            "import org.eclipse.jgit.lib.*;",
            "import java.io.File;",
            "public class Pure {",
            "  public Object detect() { return FS.detect(); }",
            "  public Object resolve(FS fs, File d) { return fs.resolve(d, \"objects\"); }",
            "  public boolean caseSensitive(FS fs) { return fs.isCaseSensitive(); }",
            "  public Object oid(String s) { return ObjectId.fromString(s).name(); }",
            "  public Object branch(Repository r) { return r.getBranch(); }",
            "  public Object setGitDir(BaseRepositoryBuilder b, File d) { return b.setGitDir(d).getGitDir(); }",
            "  public Object host() { return org.eclipse.jgit.util.SystemReader.getInstance().getHostname(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"detect", "resolve", "caseSensitive", "oid", "branch",
                    "setGitDir", "host"}) {
                assertFalse(eff(r, "com.x.Pure." + m).contains(Effect.EXEC),
                    m + " forks nothing — must NOT be Exec, got " + r.get("com.x.Pure." + m));
            }
        } finally { rm(app.getParent()); }
    }

    /** A project type that merely shares a name is a different owner and gains nothing. */
    @Test
    void control_sameNamedProjectTypeGainsNothing() throws Exception {
        Path app = compileApp(Map.of("unused/Nothing.java", "package unused; public class Nothing {}"),
            Map.of("com/mine/Git.java",
                "package com.mine;\npublic class Git { public static Git open(java.io.File d) { return null; } }",
                "com/mine/Use.java",
                "package com.mine;\npublic class Use { public Object go(java.io.File d) { return Git.open(d); } }"));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "com.mine.Use.go").isEmpty(),
                "a project Git is not jgit's — must stay pure, got " + r.get("com.mine.Use.go"));
        } finally { rm(app.getParent()); }
    }

    // ── the classifier table ───────────────────────────────────────────────────────────────────────

    /** {@code Git.open} keeps {@code Fs} at the table — the {@code Exec} half is a co-emission in
     *  {@code Candor.handleMethodInsn}, because {@code classify} returns ONE effect. Pinning both halves
     *  here is what stops a later edit "simplifying" the rule to return {@code Exec} and silently
     *  dropping the {@code Fs}. */
    @Test
    void gitOpenStaysFsAtTheTableAndIsExecInTheScan() {
        assertEquals(Effect.FS, Classifier.classify("org.eclipse.jgit.api.Git", "open",
            "(Ljava/io/File;)Lorg/eclipse/jgit/api/Git;"));
        assertTrue(Classifier.jgitForksGitSubprocess("org.eclipse.jgit.api.Git", "open",
            "(Ljava/io/File;)Lorg/eclipse/jgit/api/Git;"));
        // The Path arm of the descriptor gate mirrors the Fs rule's. No published jgit ships such an
        // overload; both are gated the same way so the two cannot answer differently if one ever appears.
        assertEquals(Effect.FS, Classifier.classify("org.eclipse.jgit.api.Git", "open", "(Ljava/nio/file/Path;)LG;"));
        assertTrue(Classifier.jgitForksGitSubprocess("org.eclipse.jgit.api.Git", "open", "(Ljava/nio/file/Path;)LG;"));
        // …and `wrap(Repository)` takes an ALREADY-BUILT repository, so it neither reads nor forks.
        assertNull(Classifier.classify("org.eclipse.jgit.api.Git", "wrap",
            "(Lorg/eclipse/jgit/lib/Repository;)Lorg/eclipse/jgit/api/Git;"));
        assertFalse(Classifier.jgitForksGitSubprocess("org.eclipse.jgit.api.Git", "wrap",
            "(Lorg/eclipse/jgit/lib/Repository;)Lorg/eclipse/jgit/api/Git;"));
    }

    /** The fork surface at the table, including the PLATFORM subclasses the abstract members dispatch to
     *  — {@code FS_POSIX.discoverGitExe} is where {@code bash --login -c "which git"} actually lives, and
     *  a rule scoped to {@code FS} alone would have missed the owner the bytecode carries. */
    @Test
    void theForkSurfaceIsExecAtTheTable() {
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.FS", "readPipe",
            "(Ljava/io/File;[Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.FS", "getGitSystemConfig", "()Ljava/io/File;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.FS", "runInShell",
            "(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/ProcessBuilder;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.FS_POSIX", "discoverGitExe", "()Ljava/io/File;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.FS_Win32", "discoverGitExe", "()Ljava/io/File;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.SystemReader", "getUserConfig",
            "()Lorg/eclipse/jgit/lib/StoredConfig;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.util.SystemReader$Default", "openSystemConfig",
            "(Lorg/eclipse/jgit/lib/Config;Lorg/eclipse/jgit/util/FS;)Lorg/eclipse/jgit/storage/file/FileBasedConfig;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.lib.BaseRepositoryBuilder", "build",
            "()Lorg/eclipse/jgit/lib/Repository;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.api.CloneCommand", "call",
            "()Lorg/eclipse/jgit/api/Git;"));
        // The hook surface — whole package, payload-carrying setters included.
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.hooks.PreCommitHook", "call", "()Ljava/lang/Void;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.hooks.CommitMsgHook", "setCommitMessage",
            "(Ljava/lang/String;)Lorg/eclipse/jgit/hooks/CommitMsgHook;"));
        // CONTROL — the §4 Object protocol is exempt from the whole-package rule.
        assertNull(Classifier.classify("org.eclipse.jgit.hooks.PreCommitHook", "toString", "()Ljava/lang/String;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.hooks.Hooks", "prePush",
            "(Lorg/eclipse/jgit/lib/Repository;Ljava/io/PrintStream;Ljava/io/PrintStream;)Lorg/eclipse/jgit/hooks/PrePushHook;"));
        assertEquals(Effect.EXEC, Classifier.classify("org.eclipse.jgit.transport.Transport", "push",
            "(Lorg/eclipse/jgit/lib/ProgressMonitor;Ljava/util/Collection;Ljava/io/OutputStream;)Lorg/eclipse/jgit/transport/PushResult;"));
        // CONTROL — `push` is charged because it runs the pre-push hook; its sibling `fetch` runs NO hook
        // and must not be dragged in with it. Note what this does NOT claim: `TransportLocal.spawn`
        // forks `git-upload-pack` on a `file://` URI, so a LOCAL fetch does reach a subprocess. That is
        // left to the `invisible` floor with the rest of the unmodelled surface and is recorded as a
        // stated residual, NOT asserted here to be pure.
        assertNull(Classifier.classify("org.eclipse.jgit.transport.Transport", "fetch",
            "(Lorg/eclipse/jgit/lib/ProgressMonitor;Ljava/util/Collection;)Lorg/eclipse/jgit/transport/FetchResult;"));
        // CONTROLS — the two carve-outs, each derived rather than assumed, and FS's inner VALUE types,
        // which the `FS_` prefix must not reach.
        assertNull(Classifier.classify("org.eclipse.jgit.util.FS", "detect", "()Lorg/eclipse/jgit/util/FS;"));
        assertNull(Classifier.classify("org.eclipse.jgit.util.FS", "searchPath",
            "(Ljava/lang/String;[Ljava/lang/String;)Ljava/io/File;"));
        assertNull(Classifier.classify("org.eclipse.jgit.util.FS$ExecutionResult", "getRc", "()I"));
        assertNull(Classifier.classify("org.eclipse.jgit.util.FS$FileStoreAttributes", "getFsTimestampResolution",
            "()Ljava/time/Duration;"));
        assertNull(Classifier.classify("org.eclipse.jgit.lib.ObjectId", "fromString",
            "(Ljava/lang/String;)Lorg/eclipse/jgit/lib/ObjectId;"));
    }

    // ── harness ────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
