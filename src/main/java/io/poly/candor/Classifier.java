package io.poly.candor;

import io.poly.candor.model.Effect;

import java.util.*;
import static io.poly.candor.Candor.*;
import static io.poly.candor.AnalysisState.*;

/** The κ effect-leaf classifier — (owner,method,desc)->effect (~1800 lines of per-library/JDK κ rules).
 *  EXTRACTED from Candor.java (refactor P1): pure, no shared-state coupling; helpers
 *  (isConventionallyPure/isAwsPureClientGetter/isLogEmitVerb/isPureHandleAccessor) stay in Candor,
 *  reached via the static import. Sole caller: Candor.analyze(). See REFACTOR_PLAN.md. */
final class Classifier {
    /** The PARAMETER segment of a method descriptor — `(Ljava/io/File;)Ljava/io/File;` → `Ljava/io/File;`.
     *  The source/sink descriptor rules (jackson/commons-io/dbunit/…) must match parameters ONLY: a pure
     *  method RETURNING a File (FileUtils.getTempDirectory) must never classify (caught by round-12's
     *  anti-fabrication pin when batch 31 first used whole-descriptor contains). */
    static String paramsOf(String desc) {
        int close = desc.indexOf(')');
        return close > 0 ? desc.substring(1, close) : desc;
    }

    /** κ dispatch: one bucket per leading owner package segment (java/javax/jakarta/org/com/io,
     *  everything else in classifyOther), so every bucket stays under HotSpot's
     *  DontCompileHugeMethods limit (8KB of bytecode) — the old single ~27KB cascade ran
     *  INTERPRETED on the hottest path of every scan. The split is a PARTITION of the original
     *  cascade: a bucket holds, in the original order, every rule that can match an owner whose
     *  first segment dispatches there, so any return (an effect, or an early `return null`
     *  pure-exit) is the same answer the single cascade gave. A rule whose owners span buckets
     *  lives ONCE in a shared* helper called from each bucket at its original cascade position
     *  (rule text is never duplicated). ADDING A RULE: put it in the bucket its owner prefix
     *  dispatches to (all buckets keep the original cascade's relative order); if the owner set
     *  spans buckets, add a shared* helper. Keep buckets under ~7.5KB: verify with
     *  `javap -c` (test/smoke.sh gates this).
     */
    static Effect classify(String owner, String method, String desc) {
        // A proven-pure accessor/factory/inert-ctor on an otherwise-effectful handle type is PURE — the
        // whole-owner rules below would fabricate the type's effect on it (the cardinal sin). Subtract
        // these explicitly; everything else on the type keeps its effect. (See isPureHandleAccessor.)
        if (isPureHandleAccessor(owner, method)) return null;
        int dot = owner.indexOf('.');
        switch (dot > 0 ? owner.substring(0, dot) : owner) {
            case "java": return classifyJava(owner, method, desc);
            case "javax": return classifyJavax(owner, method, desc);
            case "jakarta": return classifyJakarta(owner, method, desc);
            case "org": return classifyOrg(owner, method, desc);
            case "com": return classifyCom(owner, method, desc);
            case "io": return classifyIo(owner, method, desc);
            default: return classifyOther(owner, method, desc);
        }
    }

    private static Effect classifyJava(String owner, String method, String desc) {
        // Reflection / dynamic invocation — could call ANYTHING; honestly `Unknown`, never assumed
        // pure (SPEC §4 trust contract). This is the JVM's defining opacity, and the foundation of
        // the framework magic (Spring proxies, DI) candor can't otherwise see through.
        if (owner.equals("java.lang.reflect.Method") && method.equals("invoke")) return Effect.UNKNOWN;
        if (owner.equals("java.lang.reflect.Constructor") && method.equals("newInstance")) return Effect.UNKNOWN;
        if (owner.equals("java.lang.Class") && (method.equals("newInstance") || method.equals("forName")))
            return Effect.UNKNOWN;
        if (owner.equals("java.lang.reflect.Proxy") && method.equals("newProxyInstance")) return Effect.UNKNOWN;
        if (owner.equals("java.lang.invoke.MethodHandle") && method.startsWith("invoke")) return Effect.UNKNOWN;
        // Untrusted deserialization (gadget-chain RCE) + XXE-able XML parsing → Unknown (the realized effect
        // depends on the payload/config a static pass can't see). ObjectInputStream.readObject is THE classic
        // Java RCE sink; candor roots a project class's readObject CALLBACK but the readObject CALL is the sink.
        if (owner.equals("java.io.ObjectInputStream") && (method.equals("readObject") || method.equals("readUnshared")))
            return Effect.UNKNOWN;
        if (owner.equals("java.beans.XMLDecoder") && method.equals("readObject")) return Effect.UNKNOWN;
        if ((owner.equals("java.lang.foreign.SymbolLookup") && method.equals("find"))
                || (owner.equals("java.lang.foreign.Linker") && method.equals("upcallStub")))
            return Effect.UNKNOWN;
        if (owner.equals("java.lang.instrument.Instrumentation")
                && (method.equals("redefineClasses") || method.equals("retransformClasses"))) return Effect.UNKNOWN;
        // Dynamic class loading / definition — loadClass can run a static initializer (arbitrary code on first
        // touch) and defineClass materializes attacker-controlled bytecode → Unknown, same opacity as eval.
        // ClassLoader (and the URLClassLoader subclass — its ctor takes the search URLs, loadClass resolves
        // off them) + MethodHandles.Lookup.defineClass (the modern hidden-class definer).
        if (owner.equals("java.lang.ClassLoader") && (method.equals("loadClass") || method.equals("defineClass"))) return Effect.UNKNOWN;
        if (owner.equals("java.net.URLClassLoader") && (method.equals("<init>") || method.equals("loadClass"))) return Effect.UNKNOWN;
        if (owner.equals("java.lang.invoke.MethodHandles$Lookup") && method.equals("defineClass")) return Effect.UNKNOWN;

        // Filesystem — classic java.io streams + NIO file channels (the channel's identity IS file I/O).
        if (owner.equals("java.nio.file.Files")
                || owner.equals("java.io.FileInputStream") || owner.equals("java.io.FileOutputStream")
                || owner.equals("java.io.FileReader") || owner.equals("java.io.FileWriter")
                || owner.equals("java.io.RandomAccessFile") || owner.equals("java.io.File")
                || owner.equals("java.nio.channels.FileChannel")
                || owner.equals("java.nio.channels.AsynchronousFileChannel")
                // Archive readers open and read a file from disk (the ctor opens it, entries/getInputStream
                // read it); ZipEntry/JarEntry data types stay pure. (Found by a controlled JDK probe.)
                || owner.equals("java.util.zip.ZipFile") || owner.equals("java.util.jar.JarFile"))
            return Effect.FS;
        // MappedByteBuffer is file-backed (returned only by FileChannel.map), so its get*/put*/force/load
        // touch the mapped file → Fs. VERB-GATED (was whole-owner): the inherited Buffer queries
        // capacity()/position()/limit()/remaining()/order()/hasArray()/isDirect()/duplicate()/slice() are
        // PURE in-memory ops — a whole-owner rule fabricated Fs on them (cardinal sin, found by a
        // fabrication sweep). get*/put* don't collide with any pure Buffer method name. isLoaded() does a
        // mincore syscall → Fs.
        if (owner.equals("java.nio.MappedByteBuffer")
                && (method.startsWith("get") || method.startsWith("put")
                    || method.equals("force") || method.equals("load") || method.equals("isLoaded")))
            return Effect.FS;
        // FileStore disk-space/metadata stats (getTotalSpace/getUsableSpace/type/…) hit the filesystem;
        // FileDescriptor.sync is an fsync syscall. (Files.getFileStore — the open — is already Fs above.)
        if (owner.equals("java.nio.file.FileStore")
                && (method.startsWith("get") || method.equals("type") || method.equals("isReadOnly")
                    || method.equals("supportsFileAttributeView")))
            return Effect.FS;
        if (owner.equals("java.io.FileDescriptor") && method.equals("sync")) return Effect.FS;
        // Classpath RESOURCE reads (a file/jar entry off disk) — the ubiquitous config/i18n-loading idioms:
        // Class/ClassLoader.getResource*, ResourceBundle.getBundle, ServiceLoader (reads META-INF/services),
        // FileSystems.newFileSystem (mounts a jar/zip), LogManager/Preferences (OS prefs store). All Fs.
        if ((owner.equals("java.lang.Class") || owner.equals("java.lang.ClassLoader")
                || owner.equals("java.lang.Module"))
                && (method.equals("getResourceAsStream") || method.equals("getResource")
                    || method.equals("getResources") || method.equals("getSystemResourceAsStream")
                    || method.equals("getSystemResource") || method.equals("getSystemResources"))) return Effect.FS;
        if (owner.equals("java.util.ResourceBundle") && method.equals("getBundle")) return Effect.FS;
        if (owner.equals("java.util.ServiceLoader") && method.equals("load")) return Effect.FS;
        if (owner.equals("java.nio.file.FileSystems") && method.equals("newFileSystem")) return Effect.FS;
        if (owner.equals("java.util.prefs.Preferences")
                && (method.startsWith("get") || method.startsWith("put") || method.equals("remove")
                    || method.equals("flush") || method.equals("sync")
                    // removeNode/clear delete the persisted subtree/keys; export*/importPreferences read+write
                    // the backing store (batch-15: these unmodeled verbs were FLOOR-DROPPED silent under the
                    // κ-covered java.* prefix — a cardinal sin, not disclosed).
                    || method.equals("removeNode") || method.equals("clear")
                    || method.equals("exportNode") || method.equals("exportSubtree")
                    || method.equals("importPreferences"))) return Effect.FS;
        if (owner.equals("java.util.logging.LogManager") && method.equals("readConfiguration")) return Effect.FS;
        // java.util.Scanner(File)/(Path) opens and reads a file. CTOR-DESCRIPTOR-GATED: Scanner(String) is
        // pure (a string source) and Scanner(InputStream/Readable) defers to its source's owner — so gate to
        // the File/Path ctor descriptors only (no fabrication on the pure ctors). (JDK Fs-deep probe.)
        if (owner.equals("java.util.Scanner") && method.equals("<init>") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")))
            return Effect.FS;
        // PrintStream/PrintWriter/Formatter open a file directly in their (String fileName)/(File) ctors (no
        // wrapped FileOutputStream to catch elsewhere) → Fs. CTOR-DESCRIPTOR-GATED to the file-opening forms:
        // the (OutputStream)/(Writer)/(Appendable) overloads defer to the wrapped sink and stay pure (so an
        // in-memory PrintWriter(StringWriter)/PrintStream(ByteArrayOutputStream) never fabricates).
        if ((owner.equals("java.io.PrintStream") || owner.equals("java.io.PrintWriter")
                || owner.equals("java.util.Formatter"))
                && method.equals("<init>") && desc != null
                && (desc.startsWith("(Ljava/lang/String;") || desc.startsWith("(Ljava/io/File;")))
            return Effect.FS;
        // A java.io FILTER-stream close/flush DELEGATES to a wrapped stream of unknown concrete type, so its I/O
        // is undetermined → Unknown (never silent-pure). candor catches the file OPEN at the concrete ctor
        // (`new FileOutputStream`), but the deferred close/flush — reached e.g. via `super.close()` from a filter
        // subclass — performs the actual write/close syscall on the wrapped sink, which candor cannot resolve.
        // Disclose (Unknown), don't fabricate (never Fs — the wrapped sink may be in-memory). Found by the runtime
        // oracle on Apache commons-compress (CompressFilterOutputStream.close → super.close()); conformance-clean.
        // A java.io FILTER/BUFFERED stream's I/O method DELEGATES to a wrapped stream of unknown concrete
        // type — candor catches the file OPEN at the concrete ctor (`new FileOutputStream`) but the deferred
        // read/write/flush/close (reached e.g. via `super.write(...)` from a Monitor/Buffered subclass)
        // performs the actual syscall on the wrapped sink, which candor cannot resolve → Unknown (never
        // silent-pure; never fabricate Fs — the sink may be in-memory). The write side was found by the
        // runtime oracle on commons-compress (CompressFilterOutputStream.close, close/flush) and commons-vfs2
        // (MonitorOutputStream.write/flush → super.write → a RAM sink's Clock); the read side is its exact
        // mirror (a MonitorInputStream.read → super.read → unknown source). Naturally narrow: the abstract
        // declared type (`OutputStream x = new Buffered…`) has owner java/io/OutputStream and does NOT match —
        // only the exact-typed or `super.`-from-subclass call does, i.e. the delegating-subclass vein itself.
        if ((owner.equals("java.io.FilterOutputStream") || owner.equals("java.io.BufferedOutputStream")
                || owner.equals("java.io.FilterInputStream") || owner.equals("java.io.BufferedInputStream")
                || owner.equals("java.io.FilterReader") || owner.equals("java.io.BufferedReader")
                || owner.equals("java.io.FilterWriter") || owner.equals("java.io.BufferedWriter"))
                && (method.equals("close") || method.equals("flush") || method.equals("write")
                    || method.equals("read") || method.equals("skip"))) return Effect.UNKNOWN;
        // WatchService.take()/poll() block on filesystem change events. java.nio.file.Path is otherwise
        // pure path manipulation (resolve/getParent/normalize), so VERB-gate it: toRealPath resolves
        // symlinks against the live FS and register walks/stats the watched dir. (JDK Fs-deep probe.)
        if (owner.equals("java.nio.file.WatchService") && (method.equals("take") || method.equals("poll")))
            return Effect.FS;
        if (owner.equals("java.nio.file.Path") && (method.equals("toRealPath") || method.equals("register")))
            return Effect.FS;
        // Crypto KEY GENERATION draws entropy (from a SecureRandom) → Rand, like SecureRandom.nextBytes/
        // UUID.randomUUID. (JDK leaf, found by a crypto probe.) KeyFactory/SecretKeyFactory are deterministic
        // key derivation → stay pure; Cipher.doFinal is pure compute.
        if (owner.equals("java.security.KeyPairGenerator")
                && (method.equals("generateKeyPair") || method.equals("genKeyPair"))) return Effect.RAND;
        // Network — raw sockets, NIO socket channels (the channel type IS the network boundary; the
        // generic ReadableByteChannel/WritableByteChannel interfaces are NOT classified, they may wrap a
        // file or an in-memory buffer), java.net.http, and Spring's outbound HTTP clients. Without the NIO
        // channels, every NIO-based stack (Netty, async/reactive frameworks, modern high-perf I/O) was a
        // silent under-report — found by the gradle-cache soundness sweep (httpcore5 uses SocketChannel).
        // Selector.select* is the readiness-wait of every NIO reactor (Netty/Vert.x event loop) — a blocking
        // network-I/O wait; verb-gated (open/keys/selectedKeys/wakeup/close stay pure). MulticastChannel.join
        // is IGMP group join (network egress, the NIO twin of MulticastSocket.joinGroup).
        if (owner.equals("java.nio.channels.Selector")
                && (method.equals("select") || method.equals("selectNow"))) return Effect.NET;
        if (owner.equals("java.nio.channels.MulticastChannel") && method.equals("join")) return Effect.NET;
        // ['com', 'io', 'java', 'javax', 'org'] shared rule — see sharedSocketAndWireClients below
        Effect s1 = sharedSocketAndWireClients(owner, method, desc);
        if (s1 != null) return s1;
        // PKI revocation — CertPathValidator (OCSP/CRL fetch) + a network CertStore (LDAP/HTTP) make a remote
        // lookup hidden inside the JDK, the same shape as JNDI.lookup (already Net).
        if (owner.equals("java.security.cert.CertPathValidator") && method.equals("validate")) return Effect.NET;
        if (owner.equals("java.security.cert.CertStore")
                && (method.equals("getCertificates") || method.equals("getCRLs"))) return Effect.NET;
        // ['com', 'java', 'javax', 'misc', 'org'] shared rule — see sharedJdbcStatements below
        Effect s2 = sharedJdbcStatements(owner, method, desc);
        if (s2 != null) return s2;
        // java.sql.Driver.connect opens the physical connection (the layer under DriverManager) — silent-pure
        // for code that bypasses DriverManager and calls a Driver directly (pool internals, custom routing).
        if (owner.equals("java.sql.Driver") && method.equals("connect")) return Effect.DB;
        // ['java', 'javax'] shared rule — see sharedResultSet below
        Effect s3 = sharedResultSet(owner, method, desc);
        if (s3 != null) return s3;
        // DatabaseMetaData catalog queries round-trip to the server (getTables/getColumns/getPrimaryKeys/…
        // run a system-catalog SELECT). The whole-owner would FABRICATE on its many pure capability getters
        // (supportsX/getMaxX/getDatabaseProductName), so gate to the catalog-FETCH verbs only.
        if (owner.equals("java.sql.DatabaseMetaData")
                && (method.equals("getTables") || method.equals("getColumns") || method.equals("getPrimaryKeys")
                    || method.equals("getImportedKeys") || method.equals("getExportedKeys")
                    || method.equals("getIndexInfo") || method.equals("getSchemas") || method.equals("getCatalogs")
                    || method.equals("getProcedures") || method.equals("getFunctions")
                    || method.equals("getColumnPrivileges") || method.equals("getTablePrivileges")
                    || method.equals("getBestRowIdentifier") || method.equals("getVersionColumns")
                    || method.equals("getCrossReference") || method.equals("getTypeInfo")
                    || method.equals("getUDTs") || method.equals("getSuperTypes") || method.equals("getSuperTables")
                    || method.equals("getAttributes") || method.equals("getProcedureColumns")
                    || method.equals("getFunctionColumns") || method.equals("getPseudoColumns")
                    || method.equals("getClientInfoProperties") || method.equals("getTableTypes")))
            return Effect.DB;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s4 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s4 != null) return s4;
        // Subprocess
        // ProcessBuilder.start() spawns one process; the static startPipeline(List) spawns a whole pipeline
        // of them (Java 9+) — same Exec, a distinct method name the `start`-only match missed (found by an
        // Exec-deep sweep).
        if (owner.equals("java.lang.ProcessBuilder")
                && (method.equals("start") || method.equals("startPipeline"))) return Effect.EXEC;
        if (owner.equals("java.lang.Runtime") && method.equals("exec")) return Effect.EXEC;
        // java.awt.Desktop launches an EXTERNAL program (the OS default handler for a URI/file) → Exec, the
        // same capability as ProcessBuilder/Runtime.exec. VERB-gated to the launch verbs; the factory/query
        // surface (getDesktop/isDesktopSupported/isSupported/getSupportedActions/setX handlers) stays pure.
        // (Found silent-pure by a JDK κ probe.)
        if (owner.equals("java.awt.Desktop")
                && (method.equals("browse") || method.equals("open") || method.equals("edit")
                    || method.equals("print") || method.equals("mail")
                    || method.equals("browseFileDirectory") || method.equals("openHelpViewer"))) return Effect.EXEC;
        // Driving an already-spawned subprocess is Exec too — getInputStream/getErrorStream read its
        // output, getOutputStream feeds its stdin (an unmonitored data channel), waitFor blocks on it.
        // Splitting spawn (start(), in one method) from drive (these, in another) lost the effect on the
        // driver. java.lang.Process getters typed as I/O verbs; toHandle/exitValue/isAlive stay pure.
        if (owner.equals("java.lang.Process")
                && (method.equals("getInputStream") || method.equals("getOutputStream")
                    || method.equals("getErrorStream") || method.equals("waitFor")
                    // destroy/destroyForcibly send SIGTERM/SIGKILL — subprocess CONTROL (spec §1 Exec =
                    // "spawning / controlling a subprocess"); were silent-pure.
                    || method.equals("destroy") || method.equals("destroyForcibly"))) return Effect.EXEC;
        if (owner.equals("java.lang.ProcessHandle")
                && (method.equals("destroy") || method.equals("destroyForcibly"))) return Effect.EXEC;
        // System.load/loadLibrary (and the Runtime twins) load a native image and RUN its JNI init
        // (JNI_OnLoad) — arbitrary native-code execution (candor already treats a `native` body as
        // Unknown; the call that loads+triggers it must not be invisible). The gateway to every native
        // effect → Exec.
        if ((owner.equals("java.lang.System") || owner.equals("java.lang.Runtime"))
                && (method.equals("load") || method.equals("loadLibrary"))) return Effect.EXEC;
        // Environment. `Env` is the OS process ENVIRONMENT (spec §1: "environment variables"),
        // i.e. System.getenv — NOT System.getProperty/setProperty, which read/write JVM system
        // PROPERTIES (os.name, line.separator, -D flags): JVM config, not the OS environment, and
        // read pervasively at class-init (lumping them flooded a scala-library scan with a spurious
        // 14k Env — and `getProperty("os.name")` is not an env read in any case). Properties are
        // low-signal config, left unclassified like console writes (§1).
        if (owner.equals("java.lang.System") && method.equals("getenv")) return Effect.ENV;
        // `ProcessHandle.Info.arguments()/command()/commandLine()` — the process's OWN startup state,
        // which is the same channel as `getenv`. §1 defines Env as "reading environment variables / THE
        // PROCESS ENVIRONMENT", and argv arrives through the same `exec` as envp; secrets reach a program
        // that way (`--token=…`) exactly as they do through a variable. candor-rust has always charged
        // `std::env::args()`; candor-ts and candor-swift were moved to match on 2026-08-18 after a
        // cross-engine parity sweep found one question answered two ways, and this is java's spelling of
        // it. NOT the `System.getProperty` case excluded above: that is JVM `-D` config read pervasively
        // at class-init (a measured 14k spurious Env on a scala-library scan), where this is read once.
        if (owner.equals("java.lang.ProcessHandle$Info")
                && (method.equals("arguments") || method.equals("command") || method.equals("commandLine")))
            return Effect.ENV;
        // ProcessBuilder.environment() returns the live child-process env map — reading it surfaces the
        // same OS environment as getenv (an Env disclosure), writing it sets a subprocess env var.
        if (owner.equals("java.lang.ProcessBuilder") && method.equals("environment")) return Effect.ENV;
        // Clock
        if (owner.equals("java.lang.System") && (method.equals("currentTimeMillis") || method.equals("nanoTime")))
            return Effect.CLOCK;
        if (owner.equals("java.time.Clock")) return Effect.CLOCK;
        if (method.equals("now")
                && (owner.equals("java.time.Instant") || owner.equals("java.time.LocalDateTime")
                    || owner.equals("java.time.LocalDate") || owner.equals("java.time.ZonedDateTime")
                    // the rest of the java.time `.now()` surface — OffsetDateTime is very common; the
                    // partials (LocalTime/Year/YearMonth/MonthDay/OffsetTime) likewise read the clock.
                    || owner.equals("java.time.OffsetDateTime") || owner.equals("java.time.OffsetTime")
                    || owner.equals("java.time.LocalTime") || owner.equals("java.time.Year")
                    || owner.equals("java.time.YearMonth") || owner.equals("java.time.MonthDay")))
            return Effect.CLOCK;
        // Legacy date/time: the NO-ARG `new java.util.Date()` reads System.currentTimeMillis, and
        // `Calendar.getInstance()` / no-arg `new GregorianCalendar()` initialize to "now". ARITY-PRECISE:
        // `new Date(long)` / `new GregorianCalendar(y,m,d)` take a value and are pure (no clock read), so
        // gate the ctors to the no-arg descriptor to avoid fabricating Clock on the valued forms.
        if (method.equals("<init>") && "()V".equals(desc)
                && (owner.equals("java.util.Date") || owner.equals("java.util.GregorianCalendar")))
            return Effect.CLOCK;
        if (owner.equals("java.util.Calendar") && method.equals("getInstance")) return Effect.CLOCK;
        // Randomness — the concrete PRNG/CSPRNG classes (mirrors `new Random()` / `Math.random()`).
        // ThreadLocalRandom and SplittableRandom are the java.util(.concurrent) generators a probe found
        // unclassified despite Random being flagged — same effect category, added for consistency.
        if (owner.equals("java.util.Random") || owner.equals("java.security.SecureRandom")
                || owner.equals("java.util.concurrent.ThreadLocalRandom")
                || owner.equals("java.util.SplittableRandom")
                // java.util.random.RandomGenerator is the Java 17+ root interface for all PRNGs; code typed
                // to it (or to RandomGeneratorFactory.create() results) bypasses the concrete-class matches
                // above. The sub-interfaces (Jumpable/Splittable/StreamableGenerator) extend it.
                || owner.equals("java.util.random.RandomGenerator")
                || (owner.equals("java.lang.Math") && method.equals("random")))
            // isDeprecated() is a pure metadata DEFAULT method on the RandomGenerator interface (no entropy
            // draw); the whole-owner rule fabricated Rand on it (sweep [22]). isConventionallyPure guards the
            // toString/equals/hashCode surface too. Every genuine draw (next*/ints/longs/doubles) stays Rand.
            if (!method.equals("isDeprecated") && !isConventionallyPure(method))
                return Effect.RAND;
        // UUID.randomUUID() draws a v4 UUID from a SecureRandom (genuine entropy) — Rand. METHOD-precise:
        // UUID's other members (fromString/nameUUIDFromBytes/getMostSignificantBits/toString/compareTo)
        // are pure value ops, so classifying the whole owner would fabricate Rand onto them.
        if (owner.equals("java.util.UUID") && method.equals("randomUUID")) return Effect.RAND;
        // ['java', 'misc', 'org'] shared rule — see sharedLoggingFacades below
        if (isLoggingFacadesOwner(owner)) return sharedLoggingFacades(owner, method, desc);
        // Clipboard — system clipboard access (spec §1). Toolkit hands out the system clipboard/selection
        // handle; the `Clipboard` get/setContents are the read/write. Restores cross-impl vocabulary parity
        // — Clipboard was the one spec effect candor-java never emitted (the Rust impl classifies arboard).
        if ((owner.equals("java.awt.Toolkit")
                && (method.equals("getSystemClipboard") || method.equals("getSystemSelection")))
                || owner.equals("java.awt.datatransfer.Clipboard"))
            return Effect.CLIPBOARD;
        return null;
    }

    private static Effect classifyJavax(String owner, String method, String desc) {

        // ── ARBITRARY-CODE-EXECUTION / OPAQUE sinks → Unknown (could perform ANY effect; same posture as
        // reflection/Method.invoke and candor-ts's `eval()`). These run a code/expression string, deserialize
        // untrusted data (gadget-chain RCE), parse XXE-able XML, or call native code — all security sinks
        // that read SILENT-PURE (no classify row; their JDK packages are even κ-"covered" so undisclosed).
        // Scripting / expression-language eval:
        if ((owner.equals("javax.script.ScriptEngine") || owner.equals("javax.script.CompiledScript")
                || owner.equals("javax.script.Invocable") || owner.equals("javax.script.Compilable"))
                && (method.equals("eval") || method.startsWith("invoke") || method.equals("compile")))
            return Effect.UNKNOWN;
        if (owner.startsWith("javax.el.") && method.equals("getValue")) return Effect.UNKNOWN;
        if (owner.equals("javax.tools.JavaCompiler") && method.equals("run")) return Effect.UNKNOWN;
        // ['javax', 'org'] shared rule — see sharedDocumentBuilder below
        Effect s5 = sharedDocumentBuilder(owner, method, desc);
        if (s5 != null) return s5;
        if (owner.equals("javax.xml.transform.Transformer") && method.equals("transform")) return Effect.UNKNOWN;
        // javax.imageio.ImageIO — the dominant image read/write API (analog of FileReader/Files). Gate to the
        // FILE-descriptor overloads: read(File)/write(…,File) do Fs; read(URL) does Net; the stream overloads
        // (read(InputStream)/write(…,OutputStream)) wrap a caller-supplied stream and stay pure (the Fs is on
        // the underlying FileInputStream, caught at its construction).
        if (owner.equals("javax.imageio.ImageIO")) {
            if (method.equals("read") && desc.startsWith("(Ljava/io/File;")) return Effect.FS;
            if (method.equals("read") && desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
            if (method.equals("write") && desc.contains("Ljava/io/File;")) return Effect.FS;
        }
        // javax.sound AudioSystem — getAudioInputStream(File) reads the audio file → Fs, (URL) fetches → Net
        // (descriptor-gated, like ImageIO; the InputStream overload is a caller stream → pure). Found by a
        // JDK-leaf probe.
        if (owner.equals("javax.sound.sampled.AudioSystem") && method.equals("getAudioInputStream") && desc != null) {
            if (desc.startsWith("(Ljava/io/File;")) return Effect.FS;
            if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
        }
        if (owner.equals("javax.crypto.KeyGenerator") && method.equals("generateKey")) return Effect.RAND;
        if (owner.equals("javax.mail.Transport") && method.equals("send")) return Effect.NET;
        // ['jakarta', 'javax'] shared rule — see sharedServletResponse below
        Effect s6 = sharedServletResponse(owner, method, desc);
        if (s6 != null) return s6;
        // ['jakarta', 'javax'] shared rule — see sharedInvocationBuilder below
        Effect s7 = sharedInvocationBuilder(owner, method, desc);
        if (s7 != null) return s7;
        // ['jakarta', 'javax'] shared rule — see sharedRemoteEndpointAsync below
        Effect s8 = sharedRemoteEndpointAsync(owner, method, desc);
        if (s8 != null) return s8;
        // ['jakarta', 'javax'] shared rule — see sharedMarshaller below
        Effect s9 = sharedMarshaller(owner, method, desc);
        if (s9 != null) return s9;
        // ['jakarta', 'javax'] shared rule — see sharedUnmarshaller below
        Effect s10 = sharedUnmarshaller(owner, method, desc);
        if (s10 != null) return s10;
        // ['jakarta', 'javax'] shared rule — see sharedTransaction below
        Effect s11 = sharedTransaction(owner, method, desc);
        if (s11 != null) return s11;
        // ['jakarta', 'javax'] shared rule — see sharedDispatch below
        Effect s12 = sharedDispatch(owner, method, desc);
        if (s12 != null) return s12;
        // ['jakarta', 'javax'] shared rule — see sharedService below
        Effect s13 = sharedService(owner, method, desc);
        if (s13 != null) return s13;
        // ['jakarta', 'javax'] shared rule — see sharedFolder below
        Effect s14 = sharedFolder(owner, method, desc);
        if (s14 != null) return s14;
        // ['jakarta', 'javax'] shared rule — see sharedConnection below
        Effect s15 = sharedConnection(owner, method, desc);
        if (s15 != null) return s15;
        // ['jakarta', 'javax'] shared rule — see sharedQueueBrowser below
        Effect s16 = sharedQueueBrowser(owner, method, desc);
        if (s16 != null) return s16;
        // ['jakarta', 'javax'] shared rule — see sharedExternalContext below
        Effect s17 = sharedExternalContext(owner, method, desc);
        if (s17 != null) return s17;
        // ['com', 'io', 'java', 'javax', 'org'] shared rule — see sharedSocketAndWireClients below
        Effect s18 = sharedSocketAndWireClients(owner, method, desc);
        if (s18 != null) return s18;
        // ['com', 'io', 'jakarta', 'javax', 'org'] shared rule — see sharedMessagingTemplates below
        Effect s19 = sharedMessagingTemplates(owner, method, desc);
        if (s19 != null) return s19;
        // ['com', 'java', 'javax', 'misc', 'org'] shared rule — see sharedJdbcStatements below
        Effect s20 = sharedJdbcStatements(owner, method, desc);
        if (s20 != null) return s20;
        // ['java', 'javax'] shared rule — see sharedResultSet below
        Effect s21 = sharedResultSet(owner, method, desc);
        if (s21 != null) return s21;
        // RowSet.execute()/execute(Connection) runs the configured query against the DB → Db (a RowSet-only
        // verb; ResultSet has none). javax.sql.rowset.* (JdbcRowSet/CachedRowSet/…) was FLOOR-DROPPED silent
        // under the κ-covered javax.* prefix — batch-15 cardinal sin. (acceptChanges also flushes to the DB.)
        if (owner.startsWith("javax.sql.") && owner.endsWith("RowSet")
                && (method.equals("execute") || method.equals("acceptChanges"))) return Effect.DB;
        // ['jakarta', 'javax'] shared rule — see sharedEntityManager below
        Effect s22 = sharedEntityManager(owner, method, desc);
        if (s22 != null) return s22;
        // ['jakarta', 'javax'] shared rule — see sharedEntityTransaction below
        Effect s23 = sharedEntityTransaction(owner, method, desc);
        if (s23 != null) return s23;
        // ['jakarta', 'javax'] shared rule — see sharedQuery below
        Effect s24 = sharedQuery(owner, method, desc);
        if (s24 != null) return s24;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s25 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s25 != null) return s25;
        return null;
    }

    private static Effect classifyJakarta(String owner, String method, String desc) {
        if (owner.startsWith("jakarta.el.") && method.equals("getValue")) return Effect.UNKNOWN;
        // Jakarta Data repository BASE interfaces (DataRepository/BasicRepository/CrudRepository/
        // PageableRepository) — the Hibernate-6/Jakarta-Data analog of the Spring Data rule above. A call
        // typed to the base (`CrudRepository<Fruit,Integer> r; r.save(x)`) hits the datastore → Db; project
        // sub-interfaces are promoted into repoTypes by isJakartaDataRepoBase (Loader). Every declared method
        // is a store op; exclude only the Object protocol. (jakarta.data.* value types — Sort/Order/Limit/Page
        // — are NOT under jakarta.data.repository and don't end in "Repository", so they stay pure.)
        if (owner.startsWith("jakarta.data.repository.") && owner.endsWith("Repository")
                && !isConventionallyPure(method)) return Effect.DB;
        // ['jakarta', 'javax'] shared rule — see sharedServletResponse below
        Effect s26 = sharedServletResponse(owner, method, desc);
        if (s26 != null) return s26;
        // ['jakarta', 'javax'] shared rule — see sharedInvocationBuilder below
        Effect s27 = sharedInvocationBuilder(owner, method, desc);
        if (s27 != null) return s27;
        // ['jakarta', 'javax'] shared rule — see sharedRemoteEndpointAsync below
        Effect s28 = sharedRemoteEndpointAsync(owner, method, desc);
        if (s28 != null) return s28;
        // ['jakarta', 'javax'] shared rule — see sharedMarshaller below
        Effect s29 = sharedMarshaller(owner, method, desc);
        if (s29 != null) return s29;
        // ['jakarta', 'javax'] shared rule — see sharedUnmarshaller below
        Effect s30 = sharedUnmarshaller(owner, method, desc);
        if (s30 != null) return s30;
        // ['jakarta', 'javax'] shared rule — see sharedTransaction below
        Effect s31 = sharedTransaction(owner, method, desc);
        if (s31 != null) return s31;
        // ['jakarta', 'javax'] shared rule — see sharedDispatch below
        Effect s32 = sharedDispatch(owner, method, desc);
        if (s32 != null) return s32;
        // ['jakarta', 'javax'] shared rule — see sharedService below
        Effect s33 = sharedService(owner, method, desc);
        if (s33 != null) return s33;
        // ['jakarta', 'javax'] shared rule — see sharedFolder below
        Effect s34 = sharedFolder(owner, method, desc);
        if (s34 != null) return s34;
        // JBatch — JobOperator.start/restart/stop drive the job + write the (JDBC) JobRepository → Db. PURE
        // NOT touched: getJobNames/getJobInstanceCount (registry reads).
        if (owner.equals("jakarta.batch.operations.JobOperator")
                && (method.equals("start") || method.equals("restart") || method.equals("stop")
                    || method.equals("abandon"))) return Effect.DB;
        // ['jakarta', 'javax'] shared rule — see sharedConnection below
        Effect s35 = sharedConnection(owner, method, desc);
        if (s35 != null) return s35;
        // ['jakarta', 'javax'] shared rule — see sharedQueueBrowser below
        Effect s36 = sharedQueueBrowser(owner, method, desc);
        if (s36 != null) return s36;
        // ['jakarta', 'javax'] shared rule — see sharedExternalContext below
        Effect s37 = sharedExternalContext(owner, method, desc);
        if (s37 != null) return s37;
        // ['com', 'io', 'jakarta', 'javax', 'org'] shared rule — see sharedMessagingTemplates below
        Effect s38 = sharedMessagingTemplates(owner, method, desc);
        if (s38 != null) return s38;
        // ['jakarta', 'javax'] shared rule — see sharedEntityManager below
        Effect s39 = sharedEntityManager(owner, method, desc);
        if (s39 != null) return s39;
        // ['jakarta', 'javax'] shared rule — see sharedEntityTransaction below
        Effect s40 = sharedEntityTransaction(owner, method, desc);
        if (s40 != null) return s40;
        // ['jakarta', 'javax'] shared rule — see sharedQuery below
        Effect s41 = sharedQuery(owner, method, desc);
        if (s41 != null) return s41;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s42 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s42 != null) return s42;
        return null;
    }

    private static Effect classifyOrg(String owner, String method, String desc) {
        if (owner.equals("org.springframework.expression.Expression") && method.startsWith("getValue")) return Effect.UNKNOWN;
        if (owner.equals("org.mvel2.MVEL") && (method.equals("eval") || method.startsWith("execute"))) return Effect.UNKNOWN;
        if (owner.equals("org.apache.commons.jexl3.JexlExpression") && method.equals("evaluate")) return Effect.UNKNOWN;
        if (owner.equals("org.jruby.embed.ScriptingContainer") && method.startsWith("runScriptlet")) return Effect.UNKNOWN;
        if (owner.equals("org.python.util.PythonInterpreter") && (method.equals("exec") || method.equals("eval"))) return Effect.UNKNOWN;
        // ['javax', 'org'] shared rule — see sharedDocumentBuilder below
        Effect s43 = sharedDocumentBuilder(owner, method, desc);
        if (s43 != null) return s43;
        // Non-JDK deserialization / object-graph sinks — the SAME opacity class as ObjectInputStream.readObject
        // (gadget-chain RCE; the realized effect rides the payload a static pass can't see) → Unknown. Today a
        // `deny Unknown`/`deny Net` gate would PASS code that loads & runs an attacker's object graph. The
        // ubiquitous third-party offenders: SnakeYAML (load/loadAs — RCE-by-default pre-2.0), commons-lang3
        // SerializationUtils, XStream.fromXML, Kryo, Hessian.
        if (owner.equals("org.yaml.snakeyaml.Yaml") && (method.equals("load") || method.equals("loadAs"))) return Effect.UNKNOWN;
        if (owner.equals("org.apache.commons.lang3.SerializationUtils") && method.equals("deserialize")) return Effect.UNKNOWN;
        // commons-io FileUtils/IOUtils + guava Files/MoreFiles — the ubiquitous file-convenience libs (the
        // analog of the modeled java.nio.file.Files/FileInputStream/FileWriter). Verb-gated to the file
        // read/write/copy/move/delete operators; the pure helpers (closeQuietly, lineIterator builders) and
        // the in-memory stream overloads of IOUtils (toString(InputStream) is on a stream, not a file —
        // but commons-io's IOUtils is dominantly used for file streams; gate to the unambiguous file verbs).
        if ((owner.equals("org.apache.commons.io.FileUtils"))
                && (method.startsWith("read") || method.startsWith("write") || method.startsWith("copy")
                    || method.startsWith("move") || method.startsWith("delete") || method.startsWith("force")
                    || method.startsWith("touch") || method.startsWith("cleanDirectory")
                    || method.startsWith("listFiles") || method.startsWith("openInputStream")
                    || method.startsWith("openOutputStream") || method.startsWith("iterateFiles")))
            return Effect.FS;
        // Spring filesystem utilities — known-effectful members of a κ-COVERED namespace
        // (`org.springframework`), which the covered-prefix ledger otherwise can't distinguish from a pure
        // unmodeled Spring member, so they floored silently (sweep [2]: the real fix is to MODEL the member,
        // not drop the namespace's coverage). FileSystemUtils is whole-owner Fs (deleteRecursively /
        // copyRecursively both walk the live FS). FileCopyUtils.copy/copyToByteArray are Fs only in their
        // File-typed overloads (DESCRIPTOR-GATED on `Ljava/io/File;`): the InputStream/OutputStream/Reader/
        // Writer pumps defer to the stream's own owner and must stay pure (no fabrication on an in-memory copy).
        if (owner.equals("org.springframework.util.FileSystemUtils")
                && (method.equals("deleteRecursively") || method.equals("copyRecursively"))) return Effect.FS;
        if (owner.equals("org.springframework.util.FileCopyUtils")
                && (method.equals("copy") || method.equals("copyToByteArray"))
                && desc != null && desc.contains("Ljava/io/File;")) return Effect.FS;
        // jsoup PUBLIC API (the dogfood covered jsoup INTERNALS — HttpConnection/DataUtil — but not these
        // user-facing entry leaves; found silent-pure by the library κ-coverage probe). `org.jsoup.Connection`
        // is the fluent HTTP builder: url/userAgent/header/data/method return the builder (PURE), only the
        // TERMINAL get/post/execute do the round-trip → Net (verb-gated). `Jsoup.parse(File|Path,…)` reads the
        // file → Fs (descriptor-gated first arg); parse(String|InputStream,…) stays pure (in-memory / caller stream).
        if (owner.equals("org.jsoup.Connection")
                && (method.equals("get") || method.equals("post") || method.equals("execute"))) return Effect.NET;
        if (owner.equals("org.jsoup.Jsoup") && method.equals("parse") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;"))) return Effect.FS;
        // Apache POI — WorkbookFactory.create(File) opens+reads the spreadsheet from disk → Fs.
        // DESCRIPTOR-GATED on the File arg (mirrors the jackson rule): the (InputStream)/(boolean) overloads
        // defer to a caller stream / in-memory and stay pure. Covers the format-specific factory subclasses.
        if ((owner.equals("org.apache.poi.ss.usermodel.WorkbookFactory")
                || owner.equals("org.apache.poi.xssf.usermodel.XSSFWorkbookFactory")
                || owner.equals("org.apache.poi.hssf.usermodel.HSSFWorkbookFactory"))
                && method.equals("create") && desc != null && desc.startsWith("(Ljava/io/File;")) return Effect.FS;
        // Apache Commons Net FTPClient — an intrinsic network client. VERB-gated to the wire actions; the
        // setX/getX config surface stays pure (no fabrication on setBufferSize/setControlEncoding).
        if (owner.equals("org.apache.commons.net.ftp.FTPClient")) {
            switch (method) {
                case "connect": case "disconnect": case "login": case "logout":
                case "retrieveFile": case "retrieveFileStream": case "storeFile": case "storeFileStream":
                case "appendFile": case "appendFileStream": case "listFiles": case "listDirectories":
                case "listNames": case "deleteFile": case "makeDirectory": case "removeDirectory":
                case "changeWorkingDirectory": case "rename": case "sendCommand": case "getReply":
                case "completePendingCommand": case "abort":
                    return Effect.NET;
                default: break;
            }
        }
        // Flyway / Liquibase — schema migration runners. VERB-gated → Db (the static configure()/fluent
        // builders stay pure). (Liquibase's update(String,Writer) SQL-dump overloads are rare; verb-gating
        // accepts a small over-approximation there vs the common DB-hitting overloads.)
        if (owner.equals("org.flywaydb.core.Flyway")
                && (method.equals("migrate") || method.equals("clean") || method.equals("validate")
                    || method.equals("baseline") || method.equals("repair") || method.equals("info")))
            return Effect.DB;
        // JGit Git.open(File|Path) opens an on-disk repository → Fs (descriptor-gated; the builder
        // cloneRepository() stays pure until its .call()).
        if (owner.equals("org.eclipse.jgit.api.Git") && method.equals("open") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;"))) return Effect.FS;
        // Apache Commons Compress archive readers — the File/Path CONSTRUCTORS open the archive → Fs
        // (descriptor-gated ctor; the SeekableByteChannel ctor is a caller-supplied handle → stays pure).
        if ((owner.equals("org.apache.commons.compress.archivers.zip.ZipFile")
                || owner.equals("org.apache.commons.compress.archivers.sevenz.SevenZFile")
                || owner.equals("org.apache.commons.compress.archivers.tar.TarFile"))
                && method.equals("<init>") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;"))) return Effect.FS;
        // Apache Tika facade — parseToString(File|Path) reads the file → Fs, (URL) fetches → Net
        // (descriptor-gated; the InputStream overload is a caller stream → pure).
        if (owner.equals("org.apache.tika.Tika") && method.equals("parseToString") && desc != null) {
            if (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")) return Effect.FS;
            if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
        }
        // Apache PDFBox 3 Loader.loadPDF(File|Path) reads the PDF → Fs (descriptor-gated; the byte[] overload
        // is in-memory → pure).
        if (owner.equals("org.apache.pdfbox.Loader") && method.equals("loadPDF") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;"))) return Effect.FS;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 3) ──
        // Spring Data repository BASE interfaces (CrudRepository/ListCrudRepository/PagingAndSortingRepository/
        // JpaRepository/Reactive*…) — a DIRECT call on the base interface (`CrudRepository<X,Y> r; r.save(x)`)
        // hits the datastore → Db. (The 1851 detection marks PROJECT sub-interfaces; this covers the base
        // interface call site itself.) Every declared method is a store op; exclude only the Object protocol.
        if (owner.startsWith("org.springframework.data.") && owner.endsWith("Repository")
                && !isConventionallyPure(method)) return Effect.DB;
        // Apache Avro container files — DataFileReader ctor / DataFileWriter.create on a File open the file
        // off disk → Fs. desc CONTAINS java.io.File (create's File is the 2nd arg, after the Schema); the
        // SeekableInput/OutputStream overloads are caller-supplied → pure.
        if (owner.equals("org.apache.avro.file.DataFileReader") && method.equals("<init>")
                && desc != null && desc.contains("Ljava/io/File;")) return Effect.FS;
        if (owner.equals("org.apache.avro.file.DataFileWriter") && method.equals("create")
                && desc != null && desc.contains("Ljava/io/File;")) return Effect.FS;
        // Apache Commons Configuration2 fluent Configurations — the loader verbs read their source; ARG-gated:
        // a File arg → Fs, a URL arg → Net, a String arg (a path/file-name overload) → Fs. VERB-GATED (was
        // any-method): a whole-owner String-arg rule fabricated Fs on the pure builder/factory calls whose
        // String is a property-name or encoding, not a path — same precision the java.nio.file.Files family
        // already gets. The loaders are properties/xml/ini/fileBased/combined (+ their string/file/url
        // overloads); the *Builder() factories return a builder that touches no source until built → pure.
        if (owner.equals("org.apache.commons.configuration2.builder.fluent.Configurations") && desc != null
                && (method.equals("properties") || method.equals("xml") || method.equals("ini")
                    || method.equals("fileBased") || method.equals("combined"))) {
            if (desc.contains("Ljava/net/URL;")) return Effect.NET;
            if (desc.contains("Ljava/io/File;") || desc.contains("Ljava/lang/String;")) return Effect.FS;
        }
        // Spring mail — JavaMailSender/MailSender.send drives the SMTP round-trip (the raw jakarta.mail
        // Transport.send is already modeled; this is the Spring wrapper apps actually call). VERB-gated to
        // send/doSend so the JavaMailSenderImpl config setters (setHost/setPort/…) stay pure.
        if ((owner.equals("org.springframework.mail.MailSender")
                || owner.equals("org.springframework.mail.javamail.JavaMailSender")
                || owner.equals("org.springframework.mail.javamail.JavaMailSenderImpl"))
                && (method.equals("send") || method.equals("doSend"))) return Effect.NET;
        // Spring Data Redis operations — opsForValue()/opsForList()/… return *Operations whose terminal
        // get/set/… hit Redis → Db. This is the deliberate Redis labelling RECONCILIATION: every Redis
        // client now carries Db (RedisTemplate already did; Jedis/Lettuce/Redisson/these Operations were
        // Net) — Redis is a datastore, so its semantic boundary effect is Db (like JDBC-over-TCP is Db, not
        // Net). Cross-engine-consistent with candor-ts's redis→Db. Whole-owner; Object protocol excluded.
        if (owner.startsWith("org.springframework.data.redis.core.") && owner.endsWith("Operations")
                && !isConventionallyPure(method)) return Effect.DB;
        // Elasticsearch / OpenSearch low-level REST clients — performRequest is the HTTP round-trip → Net.
        if ((owner.equals("org.elasticsearch.client.RestClient") || owner.equals("org.opensearch.client.RestClient"))
                && (method.equals("performRequest") || method.equals("performRequestAsync"))) return Effect.NET;
        // AsyncHttpClient — executeRequest fires the wire request → Net.
        if (owner.equals("org.asynchttpclient.AsyncHttpClient") && method.equals("executeRequest")) return Effect.NET;
        if (owner.equals("org.apache.velocity.app.VelocityEngine")
                && (method.equals("getTemplate") || method.equals("mergeTemplate"))) return Effect.FS;
        // Apache Commons VFS — FileContent.get{Input,Output}Stream opens the resource (local scheme → Fs;
        // ftp/http schemes would be Net but the scheme isn't statically known → Fs, the common case).
        if (owner.equals("org.apache.commons.vfs2.FileContent")
                && (method.equals("getInputStream") || method.equals("getOutputStream"))) return Effect.FS;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 6) ──
        // RocksDB — embedded on-disk KV store (native JNI). No in-memory variant on this class → whole-owner
        // Fs for the I/O verbs (the open/get/put/write/merge/delete/iterator are all disk).
        if (owner.equals("org.rocksdb.RocksDB")) {
            switch (method) {
                case "open": case "openReadOnly": case "get": case "put": case "write": case "merge":
                case "delete": case "deleteRange": case "newIterator": case "multiGetAsList": case "flush":
                    return Effect.FS;
                default: break;
            }
        }
        // MapDB — model the FILE factory `DBMaker.fileDB(File|String)` as Fs (it configures a disk store).
        // NOT the shared `Maker.make()` terminal: `memoryDB().make()` reaches the same make() and must stay
        // pure (anchor mapdbMemoryMakePure).
        if (owner.equals("org.mapdb.DBMaker") && method.equals("fileDB")) return Effect.FS;
        // Lucene — `FSDirectory.open(Path)` always opens an on-disk index dir → Fs (descriptor-clean). The
        // IndexWriter.addDocument / DirectoryReader.open(Directory) leaves are AMBIGUOUS-RECEIVER (the
        // Directory may be a RAM ByteBuffersDirectory), so modelling them whole-owner would fabricate on the
        // in-memory variant — left as accepted gaps (the FSDirectory.open factory is the safe disk signal).
        if (owner.equals("org.apache.lucene.store.FSDirectory") && method.equals("open")) return Effect.FS;
        // Testcontainers — GenericContainer.start shells out to the Docker daemon → Exec; execInContainer
        // runs a command INSIDE the running container → Exec too (was silent even for direct use).
        if (owner.equals("org.testcontainers.containers.GenericContainer")
                && (method.equals("start") || method.equals("execInContainer"))) return Effect.EXEC;
        // Selenium — WebDriver.get drives a browser / talks to a remote WebDriver server over HTTP → Net.
        // OWNER-scoped (not a global `get` rule — that would collide with bean getters).
        if ((owner.equals("org.openqa.selenium.WebDriver") || owner.equals("org.openqa.selenium.remote.RemoteWebDriver"))
                && method.equals("get")) return Effect.NET;
        // Apache Camel — ProducerTemplate routes a body to an endpoint (usually remote) → Net.
        if (owner.equals("org.apache.camel.ProducerTemplate")
                && (method.startsWith("sendBody") || method.startsWith("requestBody")
                    || method.startsWith("asyncSendBody") || method.startsWith("asyncRequestBody"))) return Effect.NET;
        // JeroMQ (0MQ) — Socket.send/recv move bytes over the 0MQ socket → Net (TCP default).
        if (owner.equals("org.zeromq.ZMQ$Socket")
                && (method.startsWith("send") || method.startsWith("recv"))) return Effect.NET;
        // Apache Thrift — the SOCKET transports do the RPC wire I/O → Net. Keyed to the socket types (NOT
        // abstract TTransport, whose TMemoryBuffer subclass is in-memory → would fabricate).
        if ((owner.equals("org.apache.thrift.transport.TSocket")
                || owner.equals("org.apache.thrift.transport.TNonblockingSocket"))
                && (method.equals("open") || method.equals("read") || method.equals("write")
                    || method.equals("flush"))) return Effect.NET;
        // BouncyCastle low-level key-pair generators draw entropy → Rand (the jcajce KeyPairGenerator extends
        // java.security.KeyPairGenerator, already covered; this is the org.bouncycastle.crypto.generators.*
        // API). BC digest/cipher ops stay pure compute.
        if (owner.startsWith("org.bouncycastle.crypto.generators.") && method.equals("generateKeyPair")) return Effect.RAND;
        // ['com', 'org'] shared rule — see sharedIMap below
        Effect s44 = sharedIMap(owner, method, desc);
        if (s44 != null) return s44;
        // JDBI read path — Handle.createQuery/select builds+runs a SELECT → Db (execute/withHandle already
        // modeled; this closes the uncovered SELECT side).
        if (owner.equals("org.jdbi.v3.core.Handle")
                && (method.equals("createQuery") || method.equals("select") || method.equals("createUpdate")
                    || method.equals("createCall") || method.equals("createScript"))) return Effect.DB;
        // Spring Data Couchbase template → Db (sibling of the already-modeled Cassandra/Mongo templates).
        if (owner.equals("org.springframework.data.couchbase.core.CouchbaseTemplate")) {
            switch (method) {
                case "save": case "insert": case "upsert": case "findById": case "findByQuery":
                case "findByAnalytics": case "remove": case "removeById": case "existsById":
                    return Effect.DB;
                default: break;
            }
        }
        // Apache Commons Email (legacy javax.mail) → Net; + the legacy javax.mail.Transport.send leaf that
        // candor's jakarta.mail rule doesn't match (commons-email 1.6 still uses javax.mail).
        if (owner.equals("org.apache.commons.mail.Email")
                && (method.equals("send") || method.equals("sendMimeMessage"))) return Effect.NET;
        // im4java — *Cmd.run shells out to the ImageMagick binary (ProcessBuilder.start) → Exec.
        if (((owner.startsWith("org.im4java.core.") && owner.endsWith("Cmd"))
                || owner.equals("org.im4java.process.ProcessStarter")) && method.equals("run")) return Effect.EXEC;
        // Eclipse Jetty client — GET / Request.send do the HTTP exchange → Net.
        if (owner.equals("org.eclipse.jetty.client.HttpClient") && method.equals("GET")) return Effect.NET;
        if (owner.equals("org.eclipse.jetty.client.Request") && method.equals("send")) return Effect.NET;
        // Artemis core client — ClientProducer.send writes to the broker → Net.
        if (owner.equals("org.apache.activemq.artemis.api.core.client.ClientProducer") && method.equals("send"))
            return Effect.NET;
        // Jasypt PBE encryptors — the default RandomSaltGenerator draws a per-call salt from SecureRandom →
        // Rand (a fixed-salt config would be pure compute, but random is the default).
        if (owner.startsWith("org.jasypt.encryption.pbe.") && method.equals("encrypt")) return Effect.RAND;
        // ['io', 'org'] shared rule — see sharedLogical below
        Effect s45 = sharedLogical(owner, method, desc);
        if (s45 != null) return s45;
        // Redisson distributed objects (org.redisson.api.R*) — data verbs hit Redis → Db (the Redis
        // labelling reconciliation; all Redis clients carry Db). OWNER-scoped to the R* family (RMap extends
        // ConcurrentMap, so a java.util.Map-typed receiver is NOT matched and stays pure). EXACT data verbs
        // (getName/getCodec etc. stay pure).
        if (owner.startsWith("org.redisson.api.R")) {
            switch (method) {
                case "get": case "set": case "getAndSet": case "put": case "putIfAbsent": case "remove":
                case "add": case "contains": case "containsKey": case "isExists": case "delete":
                case "trySet": case "compareAndSet": case "fastPut": case "fastRemove": case "expire":
                    return Effect.DB;
                default: break;
            }
        }
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 10) ──
        // Apache Curator — the fluent *Builder.forPath terminal hits ZooKeeper → Net (the create()/getData()
        // builder accessors stay pure). forPath always does the ZK round-trip regardless of builder.
        if (owner.startsWith("org.apache.curator.framework.api.") && method.equals("forPath")) return Effect.NET;
        // Apache Solr — SolrClient query/add/commit/etc. do the HTTP request → Net (matches the modeled
        // Elasticsearch RestClient; search engines over HTTP).
        if (owner.equals("org.apache.solr.client.solrj.SolrClient")
                && (method.equals("query") || method.equals("add") || method.equals("commit")
                    || method.equals("deleteById") || method.equals("deleteByQuery") || method.equals("request")
                    || method.equals("getById") || method.equals("optimize"))) return Effect.NET;
        // Gremlin (TinkerPop) graph driver → Net.
        if (owner.equals("org.apache.tinkerpop.gremlin.driver.Client")
                && (method.equals("submit") || method.equals("submitAsync"))) return Effect.NET;
        // web3j — Request.send/sendAsync is the JSON-RPC transport every web3j call bottoms out in → Net.
        if (owner.equals("org.web3j.protocol.core.Request")
                && (method.equals("send") || method.equals("sendAsync"))) return Effect.NET;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 12) ──
        // Spring AI — the chat model API is HTTP inside the SDK → Net. Both owners are org.springframework.*
        // so they were FLOOR-SUPPRESSED (dropped from the report, like Spring Vault); explicit rules surface
        // them. The wire happens at the CallResponseSpec terminal (content/chatResponse/entity) and at
        // ChatModel.call(Prompt).
        // Spring AI dispatch (CallResponseSpec terminal / *ChatModel.call) — the single source of truth is
        // Rules.isSpringAiModelDispatch, which the call site also consults to refine this Net to Llm+Net.
        if (Rules.isSpringAiModelDispatch(owner, method)) return Effect.NET;
        // Telegram Bots — AbsSender.execute sends to the Bot API → Net.
        if (owner.startsWith("org.telegram.telegrambots.") && owner.endsWith("AbsSender")
                && method.equals("execute")) return Effect.NET;
        // Keycloak admin client — the JAX-RS resource proxies' ACTION verbs are admin-REST calls → Net
        // (the get(id)/sub-resource navigators that return another proxy stay pure — verb-gated to the
        // verbs that actually round-trip).
        if (owner.startsWith("org.keycloak.admin.client.resource.")
                && (method.equals("create") || method.equals("search") || method.equals("update")
                    || method.equals("remove") || method.equals("count") || method.equals("list")
                    || method.equals("add") || method.equals("findAll") || method.equals("sendVerifyEmail")
                    || method.equals("resetPassword") || method.equals("logout"))) return Effect.NET;
        // ── Spring-ecosystem FLOOR-SUPPRESSED leaves (batch 13) ──────────────────────────────────────────
        // candor treats org.springframework.* as a κ-covered prefix → an unmodeled Spring sub-library leaf is
        // DROPPED from the report entirely (worse than a disclosed Unknown). A systemic class: explicit rules
        // surface the real effect for each UNAMBIGUOUS Spring sub-lib. (The genuinely AMBIGUOUS ones —
        // MessagingTemplate→in-process DirectChannel, SessionRepository→in-memory MapSessionRepository — are
        // deliberately NOT modeled: a Net/Db rule would FABRICATE on the in-memory variant; left accepted.)
        if (owner.equals("org.springframework.batch.core.launch.JobLauncher") && method.equals("run")) return Effect.DB;
        // Spring Cloud OpenFeign load-balanced client (the FeignBlockingLoadBalancerClient + retrying wrapper
        // implement feign.Client; the floor hides them even though feign.Client.execute is modeled).
        if (owner.startsWith("org.springframework.cloud.openfeign.") && method.equals("execute")) return Effect.NET;
        // bucket continues (bytecode-size chunking, a TAIL call: fall-through only —
        // an early `return null` pure-exit above returns through the dispatcher untouched)
        return classifyOrgTail1(owner, method, desc);
    }

    private static Effect classifyOrgTail1(String owner, String method, String desc) {
        // Spring Data Elasticsearch — ElasticsearchOperations is an ES cluster client (HTTP) → Net.
        if (owner.equals("org.springframework.data.elasticsearch.core.ElasticsearchOperations")) {
            switch (method) {
                case "save": case "saveAll": case "search": case "searchForStream": case "get": case "multiGet":
                case "delete": case "deleteAll": case "index": case "bulkIndex": case "bulkUpdate":
                case "count": case "searchSimilar": case "update":
                    return Effect.NET;
                default: break;
            }
        }
        // Spring Data Neo4j — Neo4jTemplate runs Cypher over bolt (remote graph DB) → Db.
        if (owner.equals("org.springframework.data.neo4j.core.Neo4jTemplate")
                && (method.equals("save") || method.equals("saveAll") || method.equals("findById")
                    || method.equals("findAll") || method.equals("delete") || method.equals("deleteById")
                    || method.equals("deleteAll") || method.equals("count") || method.equals("existsById"))) return Effect.DB;
        // Spring LDAP — LdapTemplate issues LDAP ops over the wire → Net.
        if (owner.equals("org.springframework.ldap.core.LdapTemplate")) {
            switch (method) {
                case "search": case "lookup": case "bind": case "unbind": case "rebind": case "modifyAttributes":
                case "lookupContext": case "searchForObject": case "searchForContext": case "authenticate":
                case "list": case "listBindings": case "rename":
                    return Effect.NET;
                default: break;
            }
        }
        // ['io', 'org'] shared rule — see sharedJavalin below
        Effect s46 = sharedJavalin(owner, method, desc);
        if (s46 != null) return s46;
        // Apache Geode/GemFire Region — distributed cache, cluster round-trips → Net. Region extends
        // ConcurrentMap, so OWNER-scoped (a java.util.Map receiver stays pure, like Hazelcast/Infinispan).
        if (owner.equals("org.apache.geode.cache.Region")) {
            switch (method) {
                case "get": case "put": case "putAll": case "getAll": case "remove": case "removeAll":
                case "create": case "invalidate": case "destroy": case "putIfAbsent": case "replace":
                case "query": case "containsKey": case "containsValueForKey": case "keySetOnServer":
                    return Effect.NET;
                default: break;
            }
        }
        // SimpleJavaMail → Net (SMTP send).
        if (owner.equals("org.simplejavamail.api.mailer.Mailer") && method.equals("sendMail")) return Effect.NET;
        // docx4j — WordprocessingMLPackage/OpcPackage load/save on a File touch disk → Fs (descriptor-gated;
        // the InputStream/OutputStream overloads are caller-stream → pure).
        if (owner.startsWith("org.docx4j.openpackaging.packages.")
                && (method.equals("load") || method.equals("save"))
                && desc != null && desc.contains("Ljava/io/File;")) return Effect.FS;
        // Groovy GDK — the language's OWN stdlib I/O, which @CompileStatic compiles to direct static calls
        // (as fundamental to Groovy as java.io is to Java). ResourceGroovyMethods holds the File/URL
        // read/write extension methods (`f.text`/`f.bytes`/`f << s` → getText/getBytes/leftShift);
        // ProcessGroovyMethods.execute spawns. Was silent-pure (no classify row + the package is
        // κ-"covered", so not even disclosed). Found by a JVM-dialect sweep. Verb-gated so the pure GDK
        // surface (path/string helpers) stays pure.
        if (owner.equals("org.codehaus.groovy.runtime.ResourceGroovyMethods")) {
            if (desc != null && desc.startsWith("(Ljava/net/URL;")) return Effect.NET; // URL receiver = network egress
            if (method.startsWith("get") || method.startsWith("read") || method.startsWith("set")
                    || method.startsWith("write") || method.startsWith("append") || method.equals("leftShift")
                    || method.startsWith("eachLine") || method.startsWith("eachByte")
                    || method.startsWith("newReader") || method.startsWith("newWriter")
                    || method.startsWith("newInputStream") || method.startsWith("newOutputStream")
                    || method.startsWith("withReader") || method.startsWith("withWriter")
                    || method.startsWith("withInputStream") || method.startsWith("withOutputStream")
                    || method.startsWith("filterLine") || method.startsWith("splitEachLine"))
                return Effect.FS;
            return null;
        }
        if (owner.equals("org.codehaus.groovy.runtime.ProcessGroovyMethods") && method.startsWith("execute"))
            return Effect.EXEC;
        if ((owner.equals("org.apache.http.client.HttpClient")
                || owner.equals("org.apache.http.impl.client.CloseableHttpClient")
                || owner.equals("org.apache.hc.client5.http.classic.HttpClient")
                || owner.equals("org.apache.hc.client5.http.impl.classic.CloseableHttpClient"))
                && method.equals("execute")) return Effect.NET;
        // Apache HttpClient FLUENT facade — the same library as the modeled classic HttpClient.execute, via
        // the `Request.get(uri).execute()` one-liner entry class (hc4 + hc5).
        if ((owner.equals("org.apache.http.client.fluent.Request")
                || owner.equals("org.apache.hc.client5.http.fluent.Request"))
                && method.equals("execute")) return Effect.NET;
        // Apache HttpAsyncClient — the ASYNC sibling of the already-modeled classic HttpClient.execute (hc4
        // nio + hc5 async). execute kicks off the request.
        if ((owner.equals("org.apache.http.nio.client.HttpAsyncClient")
                || owner.equals("org.apache.http.impl.nio.client.CloseableHttpAsyncClient")
                || owner.equals("org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient")
                || owner.equals("org.apache.hc.client5.http.async.HttpAsyncClient"))
                && method.equals("execute")) return Effect.NET;
        // ['com', 'io', 'java', 'javax', 'org'] shared rule — see sharedSocketAndWireClients below
        Effect s47 = sharedSocketAndWireClients(owner, method, desc);
        if (s47 != null) return s47;
        // ['com', 'io', 'jakarta', 'javax', 'org'] shared rule — see sharedMessagingTemplates below
        Effect s48 = sharedMessagingTemplates(owner, method, desc);
        if (s48 != null) return s48;
        // ['misc', 'org'] shared rule — see sharedKvStoreClients below
        Effect s49 = sharedKvStoreClients(owner, method, desc);
        if (s49 != null) return s49;
        // ['com', 'java', 'javax', 'misc', 'org'] shared rule — see sharedJdbcStatements below
        Effect s50 = sharedJdbcStatements(owner, method, desc);
        if (s50 != null) return s50;
        if (owner.equals("org.springframework.jdbc.core.JdbcTemplate")
                || owner.equals("org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate")
                // Reactive SQL (R2DBC) + the NoSQL store templates — the reactive/store analog of
                // JdbcTemplate, all whole-owner Db. A method returning Mono/Flux off these still does the DB
                // round-trip; missing them left reactive data layers silent-pure.
                || owner.equals("org.springframework.r2dbc.core.DatabaseClient")
                || owner.equals("org.springframework.data.r2dbc.core.R2dbcEntityTemplate")
                || owner.equals("org.springframework.data.mongodb.core.MongoTemplate")
                || owner.equals("org.springframework.data.mongodb.core.ReactiveMongoTemplate")
                || owner.equals("org.springframework.data.cassandra.core.CassandraTemplate")
                || owner.equals("org.springframework.data.redis.core.RedisTemplate"))
            return Effect.DB;
        // Hibernate Session — get/load fetch by id, the query factories execute via list/uniqueResult on the
        // returned org.hibernate.query.Query, persist/save/update/delete/saveOrUpdate are the unit-of-work DB
        // ops. createQuery/createNativeQuery stay pure builders (their execution is list/uniqueResult, below).
        if (owner.equals("org.hibernate.Session")
                && (method.equals("get") || method.equals("load") || method.equals("save")
                    || method.equals("update") || method.equals("delete") || method.equals("persist")
                    || method.equals("saveOrUpdate") || method.equals("merge") || method.equals("refresh")
                    || method.equals("flush") || method.equals("byId")))
            return Effect.DB;
        if ((owner.equals("org.hibernate.query.Query") || owner.equals("org.hibernate.Query"))
                && (method.equals("list") || method.equals("uniqueResult") || method.equals("getResultList")
                    || method.equals("getSingleResult") || method.equals("executeUpdate")
                    || method.equals("scroll") || method.equals("stream")))
            return Effect.DB;
        // Hibernate 6 StatelessSession — the no-persistence-context session the Jakarta Data generated
        // repositories drive. Its CRUD verbs each issue their own SQL immediately (no unit-of-work buffering):
        // insert/update/upsert/delete (+ *Multiple batch forms), get/getIdentifier fetch, refresh/fetch.
        // The query/criteria FACTORIES (getCriteriaBuilder/createSelectionQuery/createMutationQuery/
        // createQuery/createNativeQuery) are pure BUILDERS — their execution is on the returned
        // Selection/MutationQuery (below), so excluding them avoids fabricating Db on a builder.
        if (owner.equals("org.hibernate.StatelessSession")) {
            switch (method) {
                case "insert": case "insertMultiple": case "update": case "updateMultiple":
                case "upsert": case "upsertMultiple": case "delete": case "deleteMultiple":
                case "get": case "getMultiple": case "getIdentifier": case "refresh": case "fetch":
                    return Effect.DB;
                default: break;
            }
        }
        // Hibernate 6 SelectionQuery / MutationQuery — the split successors of org.hibernate.query.Query that
        // the Jakarta Data impls and HibernateCriteriaBuilder.createQuery(...) return. ONLY the TERMINAL
        // result/execute verbs round-trip; setParameter/setMaxResults/setFirstResult/etc. are pure builders.
        if (owner.equals("org.hibernate.query.SelectionQuery")
                && (method.equals("getResultList") || method.equals("getSingleResult")
                    || method.equals("getSingleResultOrNull") || method.equals("getResultCount")
                    || method.equals("getResultStream") || method.equals("list") || method.equals("uniqueResult")
                    || method.equals("uniqueResultOptional") || method.equals("stream") || method.equals("scroll")))
            return Effect.DB;
        if (owner.equals("org.hibernate.query.MutationQuery") && method.equals("executeUpdate"))
            return Effect.DB;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s51 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s51 != null) return s51;
        // jOOQ — ONLY the TERMINAL operators run the SQL. fetch*/execute on DSLContext (`dsl.fetch(sql)`)
        // and on Query/ResultQuery execute; the builder chain (selectFrom/insertInto/query/resultQuery —
        // all return query BUILDERS) stays pure (classifying them would FABRICATE Db on a pure builder).
        if (owner.equals("org.jooq.DSLContext")
                && (method.startsWith("fetch") || method.equals("execute")
                    // batch(Query…/String…/Collection) are pure BUILDERS that return an org.jooq.Batch (no
                    // I/O until Batch.execute) — the SQL analog of selectFrom. Only the batchStore/batchInsert/
                    // batchUpdate/batchDelete/batchMerge variants execute. The bare `startsWith("batch")`
                    // FABRICATED Db on the builder (round-12 cardinal sin); gate to the executing variants.
                    || method.equals("batchStore") || method.equals("batchInsert") || method.equals("batchUpdate")
                    || method.equals("batchDelete") || method.equals("batchMerge")
                    || method.startsWith("transactionResult"))) return Effect.DB;
        if ((owner.equals("org.jooq.Query") || owner.equals("org.jooq.ResultQuery"))
                && (method.equals("execute") || method.startsWith("fetch"))) return Effect.DB;
        // MyBatis SqlSession.
        if (owner.equals("org.apache.ibatis.session.SqlSession")
                && (method.startsWith("select") || method.startsWith("insert") || method.startsWith("update")
                    || method.startsWith("delete") || method.equals("commit") || method.equals("rollback")
                    || method.equals("flushStatements"))) return Effect.DB;
        // Neo4j official driver — Session.run / Transaction.run execute the Cypher; session() is a factory.
        if ((owner.equals("org.neo4j.driver.Session") || owner.equals("org.neo4j.driver.Transaction")
                || owner.equals("org.neo4j.driver.reactive.RxSession")
                || owner.equals("org.neo4j.driver.async.AsyncSession"))
                && (method.equals("run") || method.startsWith("execute") || method.startsWith("read")
                    || method.startsWith("write"))) return Effect.DB;
        // jdbi3 — Handle/Jdbi terminal verbs run the SQL (createQuery/createUpdate return builders, stay pure).
        if ((owner.equals("org.jdbi.v3.core.Handle") || owner.equals("org.jdbi.v3.core.Jdbi"))
                && (method.equals("execute") || method.startsWith("select") || method.equals("inTransaction")
                    || method.equals("useTransaction") || method.equals("withHandle") || method.equals("useHandle")))
            return Effect.DB;
        // Spring Data JDBC aggregate template — the template sibling of the modeled JdbcTemplate/MongoTemplate
        // (the CrudRepository INTERFACE path is covered by repoTypes; this is the imperative template).
        if (owner.equals("org.springframework.data.jdbc.core.JdbcAggregateTemplate")
                && (method.equals("save") || method.startsWith("insert") || method.equals("update")
                    || method.startsWith("delete") || method.startsWith("findBy") || method.startsWith("findAll")
                    || method.equals("findById") || method.equals("count") || method.equals("existsById")))
            return Effect.DB;
        // Subprocess convenience libs (the analog of the modeled ProcessBuilder.start/Runtime.exec):
        // Apache commons-exec DefaultExecutor.execute, zt-exec ProcessExecutor.execute. The setX config
        // setters stay pure (verb-gated).
        if (owner.equals("org.apache.commons.exec.DefaultExecutor") && method.equals("execute")) return Effect.EXEC;
        if (owner.equals("org.zeroturnaround.exec.ProcessExecutor")
                && (method.equals("execute") || method.equals("executeNoTimeout") || method.equals("start")))
            return Effect.EXEC;
        // Spring's Environment.getProperty reads a MERGED source that includes the OS environment, so
        // it genuinely may surface an env var — a sound over-approximation, kept as Env.
        if (owner.equals("org.springframework.core.env.Environment") && method.equals("getProperty")) return Effect.ENV;
        // commons-lang3 SystemUtils.getEnvironmentVariable — reads an OS env var (the analog of System.getenv).
        if (owner.equals("org.apache.commons.lang3.SystemUtils") && method.equals("getEnvironmentVariable"))
            return Effect.ENV;
        // ── κ batch 28 — the LEGACY-ENTERPRISE frontier (inventory-driven: a real 2,257-class Struts
        //    app's complete 169-member call surface into these packages; see the uflexi dogfood). Each
        //    package's effectful members are classified verb-precisely HERE, and the namespaces join
        //    KAPPA_COVERED_PREFIXES so the (verified-pure) remainder floors silently instead of
        //    flooding the ledger. ──
        // Joda-Time — the pre-java.time standard. Reading the CURRENT instant is Clock: the static
        // now() on any joda type, the NO-ARG constructors of the instant-carrying types (new DateTime()
        // == DateTime.now()), and DateTimeUtils.currentTimeMillis. Everything else (parsing, value
        // arithmetic, formatters — incl. PeriodFormatter.print, which returns a String) is pure value
        // work and falls through. Descriptor-gated: new DateTime(long) is a pure value ctor.
        if (owner.startsWith("org.joda.time")) {
            if (method.equals("now")) return Effect.CLOCK;
            if (owner.equals("org.joda.time.DateTimeUtils") && method.startsWith("current")) return Effect.CLOCK;
            if (method.equals("<init>") && desc.equals("()V")
                    && (owner.equals("org.joda.time.DateTime") || owner.equals("org.joda.time.MutableDateTime")
                        || owner.equals("org.joda.time.LocalDate") || owner.equals("org.joda.time.LocalTime")
                        || owner.equals("org.joda.time.LocalDateTime") || owner.equals("org.joda.time.DateMidnight")
                        || owner.equals("org.joda.time.Instant") || owner.equals("org.joda.time.YearMonth")
                        || owner.equals("org.joda.time.MonthDay"))) return Effect.CLOCK;
            return null;
        }
        // commons-lang3 — a pure utility library EXCEPT the entropy pair (RandomStringUtils/RandomUtils:
        // every generator draws — whole-owner minus the conventionally-pure surface) and SystemProperties
        // (every getter reads the process environment → Env). StringUtils/builders/ArrayUtils/etc. are
        // pure and fall through under coverage.
        if (owner.equals("org.apache.commons.lang3.RandomStringUtils")
                || owner.equals("org.apache.commons.lang3.RandomUtils")) {
            if (!isConventionallyPure(method) && !method.equals("insecure") && !method.equals("secure")
                    && !method.equals("secureStrong")) return Effect.RAND;
            return null;
        }
        // bucket continues (bytecode-size chunking, a TAIL call: fall-through only —
        // an early `return null` pure-exit above returns through the dispatcher untouched)
        return classifyOrgTail2(owner, method, desc);
    }

    private static Effect classifyOrgTail2(String owner, String method, String desc) {
        if (owner.equals("org.apache.commons.lang3.SystemProperties")) {
            if (method.startsWith("get")) return Effect.ENV;
            return null;
        }
        if (owner.equals("org.apache.commons.lang3.SystemUtils") && method.startsWith("get")) return Effect.ENV;
        // Struts 1.x — the classic enterprise web framework; almost entirely pure bean plumbing
        // (ActionForm/ActionForward/ActionMapping/ActionMessages/DynaActionForm get/set/find/add). The
        // two effectful surfaces the inventory found: TagUtils.write/print writes tag output to the JSP
        // response → Net (the same stance as ServletResponse.getWriter — bytes to the client socket),
        // and FormFile (a multipart upload, spooled to a temp file by commons-fileupload) — reading its
        // content is Fs; the size/name accessors are pure.
        if (owner.equals("org.apache.struts.taglib.TagUtils")
                && (method.equals("write") || method.equals("print"))) return Effect.NET;
        if (owner.equals("org.apache.struts.upload.FormFile")
                && (method.equals("getInputStream") || method.equals("getFileData")
                    || method.equals("destroy"))) return Effect.FS;

        // ── κ batch 29 — the next ledger tier (same inventory method as batch 28: a real app's complete
        //    68-member frontier, triaged member-by-member). commons-validator / beanutils / displaytag /
        //    w3c.dom carry NO effectful members (pure predicates, bean plumbing, DOM value ops) — coverage
        //    only. The four below have precise effectful surfaces: ──
        // threeten-extra — java.time extensions: now() reads the clock (like Joda); Interval/value ops pure.
        if (owner.startsWith("org.threeten.extra")) {
            if (method.equals("now")) return Effect.CLOCK;
            return null;
        }
        // JDOM2 — the document MODEL is pure value work; the INPUT boundary is effectful by source:
        // build(File)/build(String systemId) reads the filesystem → Fs, build(URL) → Net. The
        // stream/reader overloads consume a CALLER-OPENED source — the open carried the effect (the
        // same relative-purity stance as the XMLOutputter stream sinks), so they fall through.
        if ((owner.equals("org.jdom2.input.SAXBuilder") || owner.equals("org.jdom2.input.StAXStreamBuilder"))
                && method.equals("build")) {
            String params = paramsOf(desc);
            if (params.contains("Ljava/net/URL;")) return Effect.NET;
            if (params.contains("Ljava/io/File;") || params.contains("Ljava/lang/String;")) return Effect.FS;
            return null;
        }
        // Ehcache — in-memory caching is pure-relative (heap tiers, Cache.get/put, config builders). The
        // effectful ACQUISITION points are precise: persistence(dir) names the disk directory → Fs (so a
        // later build/init is vouched — the config carried it; heap-only apps never fabricate Fs), and a
        // clustered cluster(URI) names the cache server → Net.
        if (owner.equals("org.ehcache.config.builders.CacheManagerBuilder") && method.equals("persistence"))
            return Effect.FS;
        if (owner.startsWith("org.ehcache.clustered") && method.equals("cluster")) return Effect.NET;

        // ── κ batch 31 — the ledger long tail, swept (same inventory discipline; 111 members triaged).
        //    Pure-surface coverage rides KAPPA_COVERED_PREFIXES; the effectful members below. Also fixes
        //    a batch-28 GAP the sweep exposed: StopWatch (both commons-lang generations) reads the clock
        //    but went silent-pure under lang3's coverage. ──
        // StopWatch reads the wall clock on start/stop/split/get*Time/createStarted → Clock, but create()
        // (an UNSTARTED stopwatch) and the format*/is* accessors read nothing (review fix — create() was
        // fabricated Clock).
        if ((owner.equals("org.apache.commons.lang3.time.StopWatch") || owner.equals("org.apache.commons.lang.time.StopWatch"))
                && !isConventionallyPure(method)
                && !method.equals("create") && !method.startsWith("format") && !method.startsWith("is"))
            return Effect.CLOCK;
        // commons-lang v2 — same shape as lang3 (batch 28): the entropy + env surfaces.
        if (owner.equals("org.apache.commons.lang.RandomStringUtils")
                || owner.equals("org.apache.commons.lang.math.RandomUtils")
                || owner.equals("org.apache.commons.lang.math.JVMRandom")) {
            if (!isConventionallyPure(method)) return Effect.RAND;
            return null;
        }
        if (owner.equals("org.apache.commons.lang.SystemUtils") && method.startsWith("get")) return Effect.ENV;
        // commons-io — the jackson source/sink stance (File/Path param → Fs, URL/URI param → Net), BUT
        // commons-io is full of PURE helpers that also take File/URL params: path arithmetic (getFile,
        // toURLs, normalize, concat, getName/getExtension/getBaseName/getPath), the file:-URL decode
        // (toFile), and the name-only file-filter predicates (accept). Carve those out first — descriptor
        // matching alone fabricated Fs/Net on them (review 0.8.3 regression). IOUtils.toString(URL) etc.
        // are NOT carved, so real fetches still classify.
        if (owner.startsWith("org.apache.commons.io")) {
            if (method.equals("toFile") || method.equals("toURLs") || method.equals("getFile")
                    || method.equals("accept") || method.startsWith("normalize") || method.startsWith("concat")
                    || method.startsWith("getName") || method.startsWith("getExtension") || method.startsWith("getBaseName")
                    || method.startsWith("getPath") || method.startsWith("getFullPath") || method.startsWith("getPrefix")
                    || method.startsWith("removeExtension") || method.startsWith("separatorsTo")
                    || method.startsWith("isExtension") || method.startsWith("indexOf") || method.startsWith("equals"))
                return null;
            String params = paramsOf(desc);
            if (params.contains("Ljava/net/URL;") || params.contains("Ljava/net/URI;")) return Effect.NET;
            if (params.contains("Ljava/io/File;") || params.contains("Ljava/nio/file/Path;")) return Effect.FS;
            // A caller-opened STREAM overload (IOUtils.read/copy/toByteArray(InputStream,…)) is PURE-RELATIVE
            // — candor's source/sink stance charges the Fs/Net at the stream's CREATION, not at each read —
            // so these fall through to null. NB the transitive runtime oracle attributes a file-backed read
            // to the read site (e.g. ZipArchiveInputStream.readFully → IOUtils.read(in,…) → Fs), which the
            // creation-site stance does not: that is a model-vs-oracle boundary (library-view under-report
            // when the open is out of scope), a deliberate stance decision, NOT a classifier miss. See
            // ClassifierLongTailTest.commonsIoFollowsTheSourceSinkStance.
            return null;
        }
        // Redisson — a Redis client: the R* handles (RMap/RLock/RBucket/…) are REMOTE data structures by
        // design — their operations are wire round-trips (→ Db, the family's Redis stance); creating a
        // client connects. Config/serialization is pure.
        if (owner.startsWith("org.redisson")) {
            // Redisson.create connects → Db. The R* data verbs are classified PRECISELY by the exact-verb
            // rule earlier in classify() (get/put/set/remove/…); a broad "any R* method → Db" here
            // FABRICATED Db on pure members (getCodec, RemoteInvocationOptions builders, RFuture plumbing),
            // so everything else falls through to pure. (review 0.8.3 regression.)
            if (owner.equals("org.redisson.Redisson") && method.startsWith("create")) return Effect.DB;
            return null;
        }
        // DbUnit — DatabaseOperation.execute runs the setup/teardown SQL → Db; datasets built FROM a
        // File read it → Fs; wrapping an existing java.sql.Connection is pure-relative (the open carried
        // Db); in-memory dataset manipulation is pure.
        if (owner.startsWith("org.dbunit")) {
            if (owner.contains("Operation") && method.equals("execute")) return Effect.DB;
            if (paramsOf(desc).contains("Ljava/io/File;")) return Effect.FS;
            return null;
        }
        // Hibernate's internal JDBC package — apps reach it for ONE pure member (BasicFormatterImpl, the
        // SQL pretty-printer, reachable from toString/log helpers everywhere — 685 fns of invisible noise
        // on the dogfood app). Covering the package obliges classifying its GENUINELY effectful internals:
        // statement execution/extraction → Db, the statement logger's emit → Log.
        if (owner.equals("org.hibernate.engine.jdbc.internal.ResultSetReturnImpl")
                && (method.startsWith("execute") || method.startsWith("extract"))) return Effect.DB;
        if (owner.equals("org.hibernate.engine.jdbc.internal.SqlStatementLogger")
                && method.startsWith("log")) return Effect.LOG;
        // AOP Alliance — proceed() EXECUTES the intercepted target (the next interceptor / the real
        // method): the reflection stance applies — disclosed Unknown, never silent-pure (coverage of the
        // namespace would otherwise silence a call that can do anything). Accessors stay pure.
        if (owner.startsWith("org.aopalliance.intercept") && method.equals("proceed")) return Effect.UNKNOWN;
        // org.hibernate.jpa — TypedParameterValue et al. are pure value wrappers; the one effectful
        // member is the persistence PROVIDER's bootstrap (opens the persistence unit → connections).
        if (owner.equals("org.hibernate.jpa.HibernatePersistenceProvider")
                && (method.startsWith("createEntityManagerFactory") || method.startsWith("createContainerEntityManagerFactory")
                    || method.startsWith("generateSchema"))) return Effect.DB;
        // ['java', 'misc', 'org'] shared rule — see sharedLoggingFacades below
        if (isLoggingFacadesOwner(owner)) return sharedLoggingFacades(owner, method, desc);
        return null;
    }

    private static Effect classifyCom(String owner, String method, String desc) {
        // com.sun.tools.javac.Main.compile — the javac entry point reads sources + writes .class files → Fs
        // (the com.sun.* analog of JavaCompiler.run; batch-20 FLOOR-dropped silent).
        if (owner.equals("com.sun.tools.javac.Main") && method.equals("compile")) return Effect.FS;
        // FFI / native execution: a native call runs arbitrary machine code (opaque like a `native` body,
        // already Unknown). JNA Function.invoke* / Library-interface dispatch / Unsafe raw memory / Panama
        // symbol+upcall / Instrumentation rewrite → Unknown; load-a-native-lib / attach-to-another-JVM → Exec.
        if (owner.equals("com.sun.jna.Function") && method.startsWith("invoke")) return Effect.UNKNOWN;
        if (owner.equals("com.sun.jna.Native") && method.equals("load")) return Effect.EXEC;  // loads + runs native lib init
        if (owner.equals("com.sun.tools.attach.VirtualMachine")
                && (method.equals("attach") || method.equals("loadAgent") || method.startsWith("loadAgent")))
            return Effect.EXEC;  // attaches to + injects code into another process
        if (owner.equals("com.thoughtworks.xstream.XStream") && method.equals("fromXML")) return Effect.UNKNOWN;
        if ((owner.equals("com.esotericsoftware.kryo.Kryo") || owner.equals("com.esotericsoftware.kryo.kryo5.Kryo"))
                && (method.equals("readObject") || method.equals("readClassAndObject"))) return Effect.UNKNOWN;
        if (owner.equals("com.caucho.hessian.io.HessianInput") && method.equals("readObject")) return Effect.UNKNOWN;
        if ((owner.equals("com.google.common.io.Files") || owner.equals("com.google.common.io.MoreFiles"))
                // NB: asByteSource/asCharSource/asByteSink/asCharSink are LAZY FACTORIES — they return a
                // Source/Sink VIEW and touch no file until a terminal read/write, so classifying them Fs
                // FABRICATED on a provably-pure builder (round-13 cardinal sin). Only the eager verbs below
                // do I/O.
                && (method.startsWith("toByteArray") || method.startsWith("write") || method.startsWith("copy")
                    || method.startsWith("move") || method.startsWith("readLines")
                    || method.startsWith("createParentDirs") || method.startsWith("touch")
                    || method.startsWith("deleteRecursively") || method.startsWith("deleteDirectoryContents")))
            return Effect.FS;
        // Jackson (one of the most-used JVM libraries) — ObjectMapper/ObjectReader/ObjectWriter
        // (de)serialization is Fs/Net ONLY in the File/Path/URL overloads (DESCRIPTOR-GATED on the FIRST
        // arg): readValue/readTree(File|Path) and writeValue(File|Path) touch the filesystem; readValue/
        // readTree(URL) fetches over the network. The String/byte[]/InputStream/OutputStream/Reader/Writer/
        // JsonParser overloads (de)serialize an in-memory value or a CALLER-supplied stream (whose effect is
        // the caller's) → stay pure (no fabrication; the kappa_libs_probe jacksonRead/WriteStringPure anchors
        // guard this). Found silent-pure by the library κ-coverage probe (kappa_libs_probe.py).
        if ((owner.equals("com.fasterxml.jackson.databind.ObjectMapper")
                || owner.equals("com.fasterxml.jackson.databind.ObjectReader")
                || owner.equals("com.fasterxml.jackson.databind.ObjectWriter")
                // Format modules (XmlMapper/YAMLMapper/CsvMapper/JavaPropsMapper/TomlMapper) SUBCLASS
                // ObjectMapper and INHERIT readValue/writeValue, so the call-site owner is the subclass —
                // missed by the exact-owner match above (batch-4 finding). All live under
                // com.fasterxml.jackson.dataformat.*.*Mapper; the descriptor gate keeps String/byte[] pure.
                || (owner.startsWith("com.fasterxml.jackson.dataformat.") && owner.endsWith("Mapper")))
                && desc != null
                && (method.equals("readValue") || method.equals("readTree") || method.equals("writeValue"))) {
            if (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")) return Effect.FS;
            if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
        }
        // Typesafe Config — parseFile(File) reads config off disk → Fs (verb-gated; parseString/parseReader
        // are in-memory/caller-stream → pure).
        if (owner.equals("com.typesafe.config.ConfigFactory")
                && (method.equals("parseFile") || method.equals("parseFileAnySyntax"))) return Effect.FS;
        // (XML parse(File) precision — the Fs that accompanies the XXE Unknown from the parse() rule above —
        //  is added in the call handler, NOT here: classify returns a single effect and that slot is already
        //  the security Unknown. See the `dir.add("Fs")` block at the XML-parse-File call site.)
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 4) ──
        // iText PDF — PdfWriter/PdfReader File|String constructors open the PDF off disk → Fs (descriptor-
        // gated ctor; the OutputStream/InputStream ctors are caller-supplied → pure).
        if ((owner.equals("com.itextpdf.kernel.pdf.PdfWriter") || owner.equals("com.itextpdf.kernel.pdf.PdfReader"))
                && method.equals("<init>") && desc != null
                && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/lang/String;"))) return Effect.FS;
        // ['com', 'io'] shared rule — see sharedBlobAsyncClient below
        Effect s52 = sharedBlobAsyncClient(owner, method, desc);
        if (s52 != null) return s52;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 5) ──
        // SSH/SFTP — JSch + SSHJ open/transfer over the SSH socket → Net (verb-gated; config setters pure).
        if (owner.equals("com.jcraft.jsch.Session") && method.equals("connect")) return Effect.NET;
        if (owner.equals("com.jcraft.jsch.ChannelSftp") && (method.equals("get") || method.equals("put"))) return Effect.NET;
        // InfluxDB write API — line-protocol over HTTP → Net (write* verbs).
        if (owner.equals("com.influxdb.client.WriteApi") && method.startsWith("write")) return Effect.NET;
        // Couchbase KV — Collection data verbs are cluster round-trips → Net (verb-gated; name/async/reactive
        // accessors stay pure).
        if (owner.equals("com.couchbase.client.java.Collection")) {
            switch (method) {
                case "get": case "upsert": case "insert": case "replace": case "remove": case "exists":
                case "getAndLock": case "getAndTouch": case "touch": case "unlock": case "mutateIn":
                case "lookupIn": case "scan":
                    return Effect.NET;
                default: break;
            }
        }
        // univocity parsers — parse(File) opens the file → Fs (descriptor-gated; parse(Reader)/(InputStream)
        // are caller-supplied → pure). Concrete parsers (CsvParser/TsvParser/FixedWidthParser) are the call
        // owners (parse is inherited from AbstractParser but emitted on the static type).
        if (owner.startsWith("com.univocity.parsers.") && owner.endsWith("Parser") && method.equals("parse")
                && desc != null && desc.startsWith("(Ljava/io/File;")) return Effect.FS;
        // ['com', 'org'] shared rule — see sharedIMap below
        Effect s53 = sharedIMap(owner, method, desc);
        if (s53 != null) return s53;
        // SaaS SDKs — the user calls the SDK's OWN resource method; the HTTP runs INSIDE the SDK (via OkHttp/
        // HttpClient) where candor can't see it from the user's call site → silent unless the SDK leaf is
        // modeled. VERB-gated on the SDK ACTION verbs (model getters/setX stay pure).
        if ((owner.startsWith("com.stripe.model.") || owner.startsWith("com.stripe.service."))
                && (method.equals("create") || method.equals("retrieve") || method.equals("update")
                    || method.equals("list") || method.equals("delete") || method.equals("cancel")
                    || method.equals("capture") || method.equals("confirm") || method.equals("search"))) return Effect.NET;
        if (owner.startsWith("com.twilio.")
                && (owner.endsWith("Creator") || owner.endsWith("Updater") || owner.endsWith("Fetcher")
                    || owner.endsWith("Deleter") || owner.endsWith("Reader"))
                && (method.equals("create") || method.equals("update") || method.equals("fetch")
                    || method.equals("delete") || method.equals("read"))) return Effect.NET;
        if ((owner.equals("com.sendgrid.SendGrid") || owner.equals("com.sendgrid.BaseInterface"))
                && (method.equals("api") || method.equals("makeCall"))) return Effect.NET;
        // Google Tink — KeysetHandle.generateNew mints key material from SecureRandom → Rand.
        if (owner.equals("com.google.crypto.tink.KeysetHandle") && method.equals("generateNew")) return Effect.RAND;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 9) ──
        // GCP services do NOT share a wire-namespace (unlike AWS) — each is its own owner. (GCS Storage
        // already modeled in an earlier batch.)
        if (owner.equals("com.google.cloud.bigquery.BigQuery")
                && (method.equals("query") || method.equals("insertAll") || method.equals("listTableData")
                    || method.equals("getQueryResults"))) return Effect.NET;
        // Firestore — the reference/query types do the fetch/write → Net (verb-gated; DocumentSnapshot.get,
        // which reads a field from an already-fetched snapshot, is a DIFFERENT owner → stays pure).
        if ((owner.equals("com.google.cloud.firestore.CollectionReference")
                || owner.equals("com.google.cloud.firestore.DocumentReference")
                || owner.equals("com.google.cloud.firestore.Query")
                || owner.equals("com.google.cloud.firestore.CollectionGroup"))
                && (method.equals("get") || method.equals("getAll") || method.equals("set")
                    || method.equals("update") || method.equals("delete") || method.equals("create")
                    || method.equals("add") || method.equals("commit"))) return Effect.NET;
        if (owner.equals("com.google.cloud.pubsub.v1.Publisher") && method.equals("publish")) return Effect.NET;
        // docker-java — *Cmd.exec() talks to the Docker daemon → Net (the dockerClient.pingCmd() builders
        // are pure).
        if (owner.startsWith("com.github.dockerjava.api.command.") && owner.endsWith("Cmd")
                && method.equals("exec")) return Effect.NET;
        // Consul (orbitz) KeyValueClient → Net.
        if (owner.equals("com.orbitz.consul.KeyValueClient")
                && (method.equals("getValue") || method.equals("getValues") || method.equals("getKeys")
                    || method.equals("putValue") || method.equals("deleteKey"))) return Effect.NET;
        // UnboundID LDAP → Net.
        if (owner.equals("com.unboundid.ldap.sdk.LDAPConnection")
                && (method.equals("search") || method.equals("bind") || method.equals("connect")
                    || method.equals("modify") || method.equals("add") || method.equals("delete")
                    || method.equals("compare") || method.equals("modifyDN"))) return Effect.NET;
        // Sardine WebDAV → Net.
        if (owner.equals("com.github.sardine.Sardine")
                && (method.equals("get") || method.equals("put") || method.equals("delete")
                    || method.equals("list") || method.equals("exists") || method.equals("move")
                    || method.equals("copy"))) return Effect.NET;
        // GCP Spanner — ReadContext.executeQuery/read run the SQL query against Spanner → Db (the singleUse()/
        // readWriteTransaction() builder accessors stay pure).
        if (owner.equals("com.google.cloud.spanner.ReadContext")
                && (method.equals("executeQuery") || method.equals("read") || method.equals("readRow")
                    || method.equals("executeQueryAsync") || method.equals("readUsingIndex"))) return Effect.DB;
        // Azure CosmosDB — CosmosContainer item ops over HTTP → Net (matches Azure Blob / DynamoDB).
        if (owner.equals("com.azure.cosmos.CosmosContainer")
                && (method.equals("readItem") || method.equals("createItem") || method.equals("upsertItem")
                    || method.equals("deleteItem") || method.equals("replaceItem") || method.equals("queryItems")
                    || method.equals("patchItem"))) return Effect.NET;
        // Azure Service Bus — sender writes to the broker → Net.
        if (owner.equals("com.azure.messaging.servicebus.ServiceBusSenderClient")
                && (method.equals("sendMessage") || method.equals("sendMessages")
                    || method.equals("scheduleMessage") || method.equals("scheduleMessages"))) return Effect.NET;
        // Azure Key Vault secrets → Net.
        if (owner.equals("com.azure.security.keyvault.secrets.SecretClient")
                && (method.equals("getSecret") || method.equals("setSecret") || method.startsWith("beginDelete")
                    || method.startsWith("listProperties") || method.equals("getDeletedSecret"))) return Effect.NET;
        // GCP Secret Manager → Net (own owner; GCP has no shared wire-namespace).
        if (owner.equals("com.google.cloud.secretmanager.v1.SecretManagerServiceClient")
                && (method.equals("accessSecretVersion") || method.equals("getSecret")
                    || method.equals("createSecret") || method.equals("addSecretVersion")
                    || method.equals("listSecrets"))) return Effect.NET;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 11) ──
        // AI/LLM clients — the model API is HTTP/gRPC inside the SDK, invisible at the user's call → Net.
        // theokanning OpenAI:
        if (owner.equals("com.theokanning.openai.service.OpenAiService") && method.startsWith("create")) return Effect.NET;
        // Anthropic SDK service classes:
        if (owner.startsWith("com.anthropic.services.")
                && (method.equals("create") || method.equals("createStreaming") || method.equals("retrieve")
                    || method.equals("list"))) return Effect.NET;
        if (owner.equals("com.aerospike.client.AerospikeClient")) {
            switch (method) {
                case "get": case "put": case "delete": case "exists": case "operate": case "query":
                case "scanAll": case "add": case "append": case "prepend": case "execute": case "truncate":
                    return Effect.NET;
                default: break;
            }
        }
        // Azure Event Hubs producer + Table Storage client → Net.
        if (owner.equals("com.azure.messaging.eventhubs.EventHubProducerClient") && method.equals("send"))
            return Effect.NET;
        if (owner.equals("com.azure.data.tables.TableClient")
                && (method.equals("createEntity") || method.equals("getEntity") || method.equals("updateEntity")
                    || method.equals("deleteEntity") || method.equals("upsertEntity")
                    || method.equals("listEntities"))) return Effect.NET;
        // Slack — MethodsClient is entirely Slack-API calls → whole-owner Net (Object protocol excluded).
        if (owner.equals("com.slack.api.methods.MethodsClient") && !isConventionallyPure(method)) return Effect.NET;
        // Okta SDK — ApiClient.invokeAPI is the generic wire leaf every Okta call bottoms out in → Net.
        if (owner.equals("com.okta.sdk.resource.client.ApiClient") && method.equals("invokeAPI")) return Effect.NET;
        // Braintree payments — TransactionGateway (and the other *Gateway resources) do the wire calls → Net
        // (BraintreeGateway.transaction() is a pure navigator → returns the gateway).
        if (owner.startsWith("com.braintreegateway.") && owner.endsWith("Gateway")
                && !owner.equals("com.braintreegateway.BraintreeGateway")
                && (method.equals("sale") || method.equals("create") || method.equals("find")
                    || method.equals("submitForSettlement") || method.equals("refund") || method.equals("void")
                    || method.equals("delete") || method.equals("update") || method.equals("search")
                    || method.equals("cancel"))) return Effect.NET;
        // Google Maps services — the *Request.await/awaitIgnoreError terminal does the HTTP call → Net
        // (geocode()/etc. return the request builder, pure until await).
        if (owner.startsWith("com.google.maps.") && owner.endsWith("Request")
                && (method.equals("await") || method.equals("awaitIgnoreError"))) return Effect.NET;
        // ClickHouse native client — execute/send run the query → Db (analytics DB, the Cassandra/Mongo/
        // Spanner family; not the HTTP-transport view).
        if (owner.equals("com.clickhouse.client.ClickHouseClient")
                && (method.equals("execute") || method.equals("send") || method.equals("executeAndWait")))
            return Effect.DB;
        // ── Non-Spring datastores (batch 13) — these were INVISIBLE-DISCLOSED (sound), modeled for precision ──
        // OrientDB session → Db.
        if (owner.equals("com.orientechnologies.orient.core.db.ODatabaseSession")
                && (method.equals("query") || method.equals("command") || method.equals("execute")
                    || method.equals("save") || method.equals("load") || method.equals("commit")
                    || method.equals("begin") || method.equals("delete"))) return Effect.DB;
        // ArangoDB database → Net (HTTP/VST; the collection()/graph() navigators stay pure).
        if (owner.equals("com.arangodb.ArangoDatabase")) {
            switch (method) {
                case "query": case "getVersion": case "getInfo": case "createCollection": case "getCollections":
                case "createGraph": case "getGraphs": case "drop": case "exists": case "create":
                case "transaction": case "getDocument": case "insertDocument":
                    return Effect.NET;
                default: break;
            }
        }
        // RethinkDB — ReqlExpr.run is the query terminal; Connection$Builder.connect opens the socket → Net.
        if (owner.equals("com.rethinkdb.gen.ast.ReqlExpr") && method.equals("run")) return Effect.NET;
        if (owner.equals("com.rethinkdb.net.Connection$Builder") && method.equals("connect")) return Effect.NET;
        // Template engines — the file-loading verb reads the template off disk → Fs (the in-memory
        // compileInline / getLiteralTemplate / Reader overloads stay pure).
        if (owner.equals("com.github.jknack.handlebars.Handlebars") && method.equals("compile")) return Effect.FS;
        if (owner.startsWith("com.github.mustachejava.") && method.equals("compile")
                && desc != null && desc.startsWith("(Ljava/lang/String;)")) return Effect.FS;
        // Alibaba OSS + Tencent COS — regional cloud object stores over HTTP → Net (same shape as AWS S3).
        if ((owner.equals("com.aliyun.oss.OSS") || owner.equals("com.aliyun.oss.OSSClient")
                || owner.equals("com.qcloud.cos.COS") || owner.equals("com.qcloud.cos.COSClient"))
                && (method.equals("getObject") || method.equals("putObject") || method.equals("deleteObject")
                    || method.equals("deleteObjects") || method.equals("listObjects") || method.equals("copyObject")
                    || method.equals("doesObjectExist") || method.equals("getObjectMetadata")
                    || method.equals("appendObject") || method.equals("uploadPart")
                    || method.equals("initiateMultipartUpload") || method.equals("completeMultipartUpload")))
            return Effect.NET;
        // metadata-extractor — ImageMetadataReader.readMetadata(File) opens the image off disk → Fs
        // (descriptor-gated; the InputStream overload is caller-stream → pure).
        if (owner.equals("com.drew.imaging.ImageMetadataReader") && method.equals("readMetadata")
                && desc != null && desc.startsWith("(Ljava/io/File;")) return Effect.FS;
        // ── Precision (batch 23): SaaS/payments/comms/cloud/search SDKs — invisible→concrete Net. All
        //    owner-scoped + verb-gated to keep in-memory builders/factories/JWT pure (anti-fab anchored). ──
        if (owner.startsWith("com.razorpay.") && owner.endsWith("Client")
                && (method.equals("create") || method.equals("fetch") || method.equals("all")
                    || method.equals("edit") || method.equals("capture") || method.equals("refund")
                    || method.equals("cancel"))) return Effect.NET;  // payments
        if (owner.startsWith("com.adyen.service.") && owner.endsWith("Api") && !isConventionallyPure(method))
            return Effect.NET;  // payments (the *Api classes are entirely remote operations)
        // bucket continues (bytecode-size chunking, a TAIL call: fall-through only —
        // an early `return null` pure-exit above returns through the dispatcher untouched)
        return classifyComTail(owner, method, desc);
    }

    private static Effect classifyComTail(String owner, String method, String desc) {
        if (owner.startsWith("com.vonage.client.") && owner.endsWith("Client")
                && (method.equals("submitMessage") || method.equals("sendMessage") || method.equals("send")))
            return Effect.NET;  // SMS/comms
        if (owner.equals("com.backblaze.b2.client.B2StorageClient")
                && (method.startsWith("upload") || method.startsWith("download") || method.equals("getFileInfo")
                    || method.startsWith("deleteFile") || method.startsWith("listFile") || method.startsWith("copy")))
            return Effect.NET;  // B2 object store
        if (owner.equals("com.cloudinary.Uploader")
                && (method.startsWith("upload") || method.equals("destroy") || method.equals("rename")
                    || method.equals("explicit"))) return Effect.NET;  // media/cloud
        if ((owner.equals("com.meilisearch.sdk.Index")
                && (method.equals("search") || method.startsWith("addDocuments") || method.startsWith("updateDocuments")
                    || method.startsWith("deleteDocument") || method.startsWith("getDocument")))
                || (owner.equals("com.meilisearch.sdk.Client")
                    && (method.equals("createIndex") || method.equals("deleteIndex") || method.equals("getIndexes"))))
            return Effect.NET;  // search SaaS (Client.index() navigator stays pure)
        if (owner.equals("com.mixpanel.mixpanelapi.MixpanelAPI")
                && (method.equals("sendMessage") || method.equals("deliver"))) return Effect.NET;  // analytics
        if (owner.equals("com.algolia.api.SearchClient")
                && (method.startsWith("save") || method.startsWith("search") || method.startsWith("delete")
                    || method.startsWith("getObject") || method.startsWith("partialUpdate")
                    || method.startsWith("batch"))) return Effect.NET;  // search SaaS
        if (owner.equals("com.contentful.java.cda.FetchQuery")
                && (method.equals("all") || method.equals("one"))) return Effect.NET;  // headless CMS terminal
        // ── Precision (batch 24) — last SaaS-Net pass (vein mined out). All body-confirmed wire calls. ──
        // Firebase Admin — FCM push + Auth admin → Net. NOT verifyIdToken (local cached-key JWT verify) or
        // createCustomToken (local JWT sign) — those are in-memory crypto, anchored pure.
        if (owner.equals("com.google.firebase.messaging.FirebaseMessaging")
                && (method.startsWith("send") || method.equals("subscribeToTopic")
                    || method.equals("unsubscribeFromTopic"))) return Effect.NET;
        if ((owner.equals("com.google.firebase.auth.FirebaseAuth")
                || owner.equals("com.google.firebase.auth.AbstractFirebaseAuth"))
                && (method.equals("createUser") || method.equals("getUser") || method.equals("updateUser")
                    || method.equals("deleteUser") || method.startsWith("getUserBy") || method.equals("listUsers")
                    || method.equals("setCustomUserClaims") || method.equals("revokeRefreshTokens")
                    || method.startsWith("generate") || method.equals("importUsers"))) return Effect.NET;
        // Email SaaS — Postmark / Mailjet wire terminals → Net.
        if (owner.equals("com.postmarkapp.postmark.client.ApiClient") && method.equals("deliverMessage"))
            return Effect.NET;
        if (owner.equals("com.mailjet.client.MailjetClient")
                && (method.equals("post") || method.equals("get") || method.equals("put") || method.equals("delete")))
            return Effect.NET;
        // SMS/comms — MessageBird / Plivo → Net (Plivo's Creator/Updater/... terminals, like Twilio).
        if (owner.equals("com.messagebird.MessageBirdClient") && method.startsWith("send")) return Effect.NET;
        if (owner.startsWith("com.plivo.api.models.")
                && (method.equals("create") || method.equals("update") || method.equals("fetch")
                    || method.equals("delete"))) return Effect.NET;
        // Realtime push — Pusher.trigger / Ably Channel.publish → Net.
        if ((owner.equals("com.pusher.rest.Pusher") || owner.equals("com.pusher.rest.PusherAbstract"))
                && method.equals("trigger")) return Effect.NET;
        // Observability SaaS — New Relic *BatchSender.sendBatch (synchronous wire; TelemetryClient.sendBatch
        // is the deferred/buffered void variant → anchored pure).
        if (owner.startsWith("com.newrelic.telemetry.") && owner.endsWith("BatchSender")
                && method.equals("sendBatch")) return Effect.NET;
        if (owner.equals("com.google.api.client.http.HttpRequest") && method.equals("execute")) return Effect.NET;
        // ['com', 'misc'] shared rule — see sharedAwsSdkClients below
        Effect s54 = sharedAwsSdkClients(owner, method, desc);
        if (s54 != null) return s54;
        // ['com', 'io', 'java', 'javax', 'org'] shared rule — see sharedSocketAndWireClients below
        Effect s55 = sharedSocketAndWireClients(owner, method, desc);
        if (s55 != null) return s55;
        // ['com', 'io', 'jakarta', 'javax', 'org'] shared rule — see sharedMessagingTemplates below
        Effect s56 = sharedMessagingTemplates(owner, method, desc);
        if (s56 != null) return s56;
        // ['com', 'java', 'javax', 'misc', 'org'] shared rule — see sharedJdbcStatements below
        Effect s57 = sharedJdbcStatements(owner, method, desc);
        if (s57 != null) return s57;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s58 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s58 != null) return s58;
        // ── Raw data-store DRIVERS (the layer UNDER the Spring templates already modeled above). A non-Spring
        // app — or Spring code typed to the driver — calls these directly; they were silent-pure though their
        // Spring-template analog (MongoTemplate/CassandraTemplate/RedisTemplate/R2dbc) IS modeled, an
        // inconsistency a completeness sweep keeps re-finding. Verb-gated so the BUILDERS/getters of each
        // driver stay pure (no fabrication on a query builder / cached-metadata getter).
        // MongoDB driver (sync + reactivestreams). MongoCollection carries the CRUD round-trips; the
        // database/client handles only the getCollection/getDatabase navigation (also a round-trip on first
        // use, but the I/O that matters is the collection op). Gate to the operation verbs.
        if ((owner.equals("com.mongodb.client.MongoCollection")
                || owner.equals("com.mongodb.reactivestreams.client.MongoCollection"))
                && (method.startsWith("find") || method.startsWith("insert") || method.startsWith("update")
                    || method.startsWith("replace") || method.startsWith("delete") || method.equals("aggregate")
                    || method.equals("countDocuments") || method.equals("estimatedDocumentCount")
                    || method.equals("distinct") || method.startsWith("bulkWrite") || method.startsWith("watch")
                    || method.startsWith("createIndex") || method.startsWith("drop")
                    || method.startsWith("findOneAndUpdate") || method.startsWith("findOneAndReplace")
                    || method.startsWith("findOneAndDelete") || method.startsWith("mapReduce")))
            return Effect.DB;
        // Datastax Cassandra driver (the dominant CqlSession).
        if (owner.equals("com.datastax.oss.driver.api.core.CqlSession")
                && (method.startsWith("execute") || method.startsWith("prepare"))) return Effect.DB;

        // ── κ batch 30 — Jackson (com.fasterxml.jackson: core/databind/annotation/datatype/…), the
        //    ubiquitous JSON stack. The API is uniformly shaped: every read/write ENTRY POINT that names
        //    its own source/sink does so via a File / Path / URL parameter (readValue(File), readTree(URL),
        //    writeValue(File), createParser(File), …) — so ONE descriptor-driven rule classifies the whole
        //    surface without enumerating classes: a File/Path parameter is a filesystem source or sink →
        //    Fs; a URL parameter is fetched → Net. Everything else (String/bytes/Reader/InputStream/
        //    DataOutput overloads, writeValueAsString, generators writing fields, config, annotations) is
        //    pure or pure-RELATIVE — the caller-opened source/sink carried the effect (the JDOM2 stance). ──
        if (owner.startsWith("com.fasterxml.jackson")) {
            String params = paramsOf(desc);
            if (params.contains("Ljava/net/URL;")) return Effect.NET;
            if (params.contains("Ljava/io/File;") || params.contains("Ljava/nio/file/Path;")) return Effect.FS;
            return null;
        }
        // Twilio — the SDK's uniform terminal pattern: Creator/Reader/Fetcher/Updater/Deleter execute the
        // REST call via create/read/fetch/update/delete (sync + async); ResourceSet ITERATION lazily
        // fetches further pages (a wire call hiding in a for-loop). The rest is value beans + config.
        if (owner.startsWith("com.twilio")) {
            if ((owner.endsWith("Creator") || owner.endsWith("Reader") || owner.endsWith("Fetcher")
                    || owner.endsWith("Updater") || owner.endsWith("Deleter"))
                    && (method.equals("create") || method.equals("read") || method.equals("fetch")
                        || method.equals("update") || method.equals("delete")
                        || method.equals("createAsync") || method.equals("readAsync") || method.equals("fetchAsync")
                        || method.equals("updateAsync") || method.equals("deleteAsync"))) return Effect.NET;
            if (owner.equals("com.twilio.base.ResourceSet") && (method.equals("iterator") || method.equals("getPage")))
                return Effect.NET;
            if (owner.equals("com.twilio.http.TwilioRestClient") && method.equals("request")) return Effect.NET;
            return null;
        }
        // javacsv — the path-taking constructors open the file; Reader/Writer-based ones are pure-relative.
        if ((owner.equals("com.csvreader.CsvReader") || owner.equals("com.csvreader.CsvWriter"))
                && method.equals("<init>") && desc.startsWith("(Ljava/lang/String;")) return Effect.FS;
        return null;
    }

    private static Effect classifyIo(String owner, String method, String desc) {
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 2) ──
        // Netty — the async network transport. VERB-gated (the config/accessor surface — group/channel/
        // handler/option/pipeline/alloc/id — stays pure). Bootstrap.connect / ServerBootstrap.bind open the
        // socket; the ChannelOutboundInvoker family (Channel/ChannelHandlerContext/ChannelPipeline) write/
        // connect/flush/bind to it.
        if (owner.equals("io.netty.bootstrap.Bootstrap") && method.equals("connect")) return Effect.NET;
        if (owner.equals("io.netty.bootstrap.ServerBootstrap") && method.equals("bind")) return Effect.NET;
        if ((owner.equals("io.netty.channel.Channel") || owner.equals("io.netty.channel.ChannelHandlerContext")
                || owner.equals("io.netty.channel.ChannelOutboundInvoker")
                || owner.equals("io.netty.channel.ChannelPipeline"))
                && (method.equals("write") || method.equals("writeAndFlush") || method.equals("connect")
                    || method.equals("flush") || method.equals("bind"))) return Effect.NET;
        // gRPC low-level ClientCall (the generated stubs' blockingUnaryCall is already modeled; this closes
        // streaming / hand-rolled calls that drive ClientCall directly).
        if (owner.equals("io.grpc.ClientCall")
                && (method.equals("sendMessage") || method.equals("halfClose") || method.equals("start")
                    || method.equals("request"))) return Effect.NET;
        // Lettuce — sync/async/reactive Redis command interfaces (RedisCommands and its RedisStringCommands/
        // RedisKeyCommands/… supers). Redis is a datastore → Db (the deliberate Redis labelling
        // reconciliation: all Redis clients carry Db, matching RedisTemplate + candor-ts's redis→Db, like
        // JDBC-over-TCP is Db not Net). Whole command-interface surface; the Object protocol stays pure.
        if (owner.startsWith("io.lettuce.core.api.") && owner.endsWith("Commands")
                && !isConventionallyPure(method)) return Effect.DB;
        // ['com', 'io'] shared rule — see sharedBlobAsyncClient below
        Effect s59 = sharedBlobAsyncClient(owner, method, desc);
        if (s59 != null) return s59;
        // dotenv-java — Dotenv.load reads the .env file → Fs.
        if ((owner.equals("io.github.cdimascio.dotenv.Dotenv")
                || owner.equals("io.github.cdimascio.dotenv.DotenvBuilder")) && method.equals("load")) return Effect.FS;
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 8) ──
        // Sentry — capture* sends to the Sentry transport → Net (async-queued; Net is sound).
        if (owner.equals("io.sentry.Sentry") && method.startsWith("capture")) return Effect.NET;
        // OpenTelemetry OTLP exporter — SpanExporter.export flushes spans over the wire → Net. (Span.end()
        // is DEFERRED to the batch processor — deliberately NOT modeled; would fabricate on every span.)
        if (owner.equals("io.opentelemetry.sdk.trace.export.SpanExporter") && method.equals("export")) return Effect.NET;
        // Kubernetes (fabric8) — the DSL TERMINAL verbs hit the API server → Net (the withName/inNamespace
        // filter accessors are pure DSL views and not in the verb set).
        if (owner.startsWith("io.fabric8.kubernetes.client.dsl.")) {
            switch (method) {
                case "list": case "create": case "get": case "delete": case "replace": case "update":
                case "patch": case "edit": case "watch": case "createOrReplace": case "serverSideApply":
                case "getLog": case "exec": case "getList":
                    return Effect.NET;
                default: break;
            }
        }
        // ['io', 'org'] shared rule — see sharedLogical below
        Effect s60 = sharedLogical(owner, method, desc);
        if (s60 != null) return s60;
        // etcd jetcd KV → Net.
        if (owner.equals("io.etcd.jetcd.KV")
                && (method.equals("get") || method.equals("put") || method.equals("delete")
                    || method.equals("txn"))) return Effect.NET;
        // RSocket reactive RPC → Net (returns Mono/Flux; wire deferred — Net is sound).
        if (owner.equals("io.rsocket.RSocket")
                && (method.equals("requestResponse") || method.equals("fireAndForget")
                    || method.equals("requestStream") || method.equals("requestChannel")
                    || method.equals("metadataPush"))) return Effect.NET;
        // Vector DBs — gRPC/HTTP data plane → Net (owner-scoped verb sets).
        if (owner.equals("io.pinecone.clients.Index")
                && (method.equals("upsert") || method.equals("query") || method.equals("fetch")
                    || method.equals("update") || method.equals("deleteByIds") || method.equals("deleteAll")
                    || method.equals("describeIndexStats") || method.equals("list"))) return Effect.NET;
        if (owner.equals("io.qdrant.client.QdrantClient") && method.endsWith("Async")) return Effect.NET;
        if (owner.equals("io.milvus.client.MilvusServiceClient")) {
            switch (method) {
                case "search": case "insert": case "query": case "delete": case "upsert": case "get":
                case "createCollection": case "dropCollection": case "loadCollection": case "flush":
                    return Effect.NET;
                default: break;
            }
        }
        // ['io', 'org'] shared rule — see sharedJavalin below
        Effect s61 = sharedJavalin(owner, method, desc);
        if (s61 != null) return s61;
        if (owner.equals("io.pebbletemplates.pebble.PebbleEngine") && method.equals("getTemplate")) return Effect.FS;
        // ── Precision upgrades (batch 22): 3rd-party libs candor already DISCLOSED invisible (sound) —
        //    modeled to the CONCRETE effect (more actionable than invisible). NOT cardinal sins. ──
        // REST Assured — the HTTP verb terminals fire the request → Net (given()/when() builders stay pure).
        if ((owner.equals("io.restassured.RestAssured")
                || owner.equals("io.restassured.specification.RequestSender")
                || owner.equals("io.restassured.specification.RequestSpecification"))
                && (method.equals("get") || method.equals("post") || method.equals("put")
                    || method.equals("delete") || method.equals("patch") || method.equals("head")
                    || method.equals("options"))) return Effect.NET;
        if ((owner.equals("io.ably.lib.rest.Channel") || owner.equals("io.ably.lib.rest.ChannelBase"))
                && method.equals("publish")) return Effect.NET;
        // gRPC CLIENT calls — candor roots the gRPC SERVER `*ImplBase` (StreamObserver) but the client path
        // was unmodeled. The blocking/async/future stub verbs funnel through io.grpc.stub.ClientCalls (the
        // generated stub's method calls these, so a typed-stub call propagates). Channel.newCall is NOT here
        // — it only CREATES a ClientCall object (no wire I/O until start/sendMessage), so it stays pure.
        if (owner.equals("io.grpc.stub.ClientCalls")
                && (method.startsWith("blocking") || method.startsWith("async") || method.startsWith("futureUnary")))
            return Effect.NET;
        // Micronaut HTTP client — exchange/retrieve EXECUTE the request (toBlocking() only adapts, stays pure).
        if ((owner.equals("io.micronaut.http.client.HttpClient")
                || owner.equals("io.micronaut.http.client.BlockingHttpClient")
                || owner.startsWith("io.micronaut.http.client.Reactive"))
                && (method.equals("exchange") || method.equals("retrieve"))) return Effect.NET;
        // Vert.x — get/post on WebClient build an HttpRequest (pure); the TERMINAL `send*` transmits. For the
        // core client the terminal is HttpClientRequest.send/end. Gate to the terminals so builders stay pure.
        if (owner.equals("io.vertx.ext.web.client.HttpRequest") && method.startsWith("send")) return Effect.NET;
        if (owner.equals("io.vertx.core.http.HttpClientRequest")
                && (method.equals("send") || method.equals("end"))) return Effect.NET;
        // ['com', 'io', 'java', 'javax', 'org'] shared rule — see sharedSocketAndWireClients below
        Effect s62 = sharedSocketAndWireClients(owner, method, desc);
        if (s62 != null) return s62;
        // ['com', 'io', 'jakarta', 'javax', 'org'] shared rule — see sharedMessagingTemplates below
        Effect s63 = sharedMessagingTemplates(owner, method, desc);
        if (s63 != null) return s63;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s64 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s64 != null) return s64;
        // R2DBC reactive-SQL SPI — the reactive analog of JDBC. Connection.createStatement BUILDS (pure);
        // Statement.execute / Batch.execute / ConnectionFactory.create round-trip.
        if ((owner.equals("io.r2dbc.spi.Statement") || owner.equals("io.r2dbc.spi.Batch"))
                && method.equals("execute")) return Effect.DB;
        if (owner.equals("io.r2dbc.spi.ConnectionFactory") && method.equals("create")) return Effect.DB;
        // jjwt — building/signing/verifying is pure CPU, but the parse* family VALIDATES exp/nbf against
        // the system clock → Clock (a token that parses fine now can fail in an hour — that is clock
        // dependence, exactly what the effect names). Key GENERATION draws entropy → Rand.
        if (owner.startsWith("io.jsonwebtoken")) {
            if (owner.equals("io.jsonwebtoken.security.Keys")
                    && (method.startsWith("secretKeyFor") || method.startsWith("keyPairFor")
                        || method.startsWith("password"))) return Effect.RAND;
            // parse* validates exp/nbf → Clock, but ONLY when it actually parses a token (takes the token
            // arg). Jwts.parser()/parserBuilder() are no-arg factories that read no clock (review fix).
            if (method.startsWith("parse") && !paramsOf(desc).isEmpty()) return Effect.CLOCK;
            return null;
        }
        // Spring Cloud AWS SES — the mail sender's send is the SES call.
        if (owner.startsWith("io.awspring.cloud.ses") && method.startsWith("send")) return Effect.NET;
        return null;
    }

    private static Effect classifyOther(String owner, String method, String desc) {
        // Groovy dynamic dispatch IS reflection: MetaClass/GroovyObject.invokeMethod resolves the target
        // at runtime through the metaclass registry and can call anything (the engine's own provenance
        // trace ran through ExpandoMetaClass.invokeMethod into ProcessGroovyMethods.execute). Honest
        // Unknown for consumers, exactly like Method.invoke.
        if ((owner.startsWith("groovy.lang.MetaClass") || owner.equals("groovy.lang.GroovyObject")
                || owner.equals("groovy.lang.MetaObjectProtocol") || owner.equals("groovy.lang.GroovyShell")
                || owner.equals("groovy.lang.Script"))
                && (method.startsWith("invoke") || method.equals("run") || method.equals("evaluate")))
            return Effect.UNKNOWN;
        if (owner.equals("ognl.Ognl") && (method.equals("getValue") || method.equals("setValue"))) return Effect.UNKNOWN;
        if (owner.equals("groovy.util.Eval") || owner.equals("groovy.lang.GroovyClassLoader")) return Effect.UNKNOWN;
        if (owner.equals("bsh.Interpreter") && method.equals("eval")) return Effect.UNKNOWN;
        if (owner.equals("clojure.lang.Compiler") && method.equals("eval")) return Effect.UNKNOWN;
        if ((owner.equals("sun.misc.Unsafe") || owner.equals("jdk.internal.misc.Unsafe"))
                && (method.endsWith("Memory") || method.startsWith("put") || method.startsWith("get")
                    || method.equals("defineClass") || method.equals("defineAnonymousClass")
                    || method.equals("allocateInstance")))
            return Effect.UNKNOWN;
        if (owner.equals("liquibase.Liquibase")
                && (method.equals("update") || method.equals("rollback") || method.equals("dropAll")
                    || method.equals("changeLogSync") || method.equals("forceReleaseLocks")))
            return Effect.DB;
        // OpenFeign — the SPI the generated @RequestLine proxy delegates the wire-send to (the user interface
        // has no body, so feign.Client.execute is the honest leaf). The Default/okhttp/httpclient adapters
        // all implement it.
        if (owner.equals("feign.Client") && method.equals("execute")) return Effect.NET;
        // Thumbnailator — Thumbnails.of(File...) reads the image off disk → Fs (the of(BufferedImage)/
        // (InputStream) overloads are in-memory/caller-stream → pure).
        if (owner.equals("net.coobird.thumbnailator.Thumbnails") && method.equals("of") && desc != null
                && desc.startsWith("([Ljava/io/File;")) return Effect.FS;
        if ((owner.equals("net.schmizz.sshj.SSHClient") || owner.equals("net.schmizz.sshj.SocketClient"))
                && method.equals("connect")) return Effect.NET;
        // FreeMarker / Velocity — getTemplate reads the template file off disk → Fs; Velocity mergeTemplate
        // reads the named template too. (The render process(model,Writer)/merge(ctx,Writer) is caller-stream
        // → pure.)
        if (owner.equals("freemarker.template.Configuration") && method.equals("getTemplate")) return Effect.FS;
        // Reactor Netty HttpClient response terminals → Net (the get()/post() request builders stay pure).
        if (owner.equals("reactor.netty.http.client.HttpClient$ResponseReceiver") && method.startsWith("response"))
            return Effect.NET;
        // Tess4J — doOCR(File) reads the image off disk → Fs (descriptor-gated; doOCR(BufferedImage) is
        // in-memory → pure). The JNA-native OCR itself is in-process (not a subprocess), so Fs — the certain
        // file read — is the sound classification, not Exec.
        if ((owner.equals("net.sourceforge.tess4j.Tesseract") || owner.equals("net.sourceforge.tess4j.ITesseract"))
                && method.equals("doOCR") && desc != null && desc.contains("Ljava/io/File;")) return Effect.FS;
        // Unirest — the as* terminals execute the request → Net (asFile also writes a file, but Net covers
        // the wire effect).
        if (owner.startsWith("kong.unirest.")) {
            switch (method) {
                case "asString": case "asJson": case "asObject": case "asBytes": case "asEmpty":
                case "asFile": case "asPaged":
                    return Effect.NET;
                default: break;
            }
        }
        // Chronicle Queue — the builder's build() opens/creates the on-disk memory-mapped queue dir → Fs
        // (Chronicle Queue is always file-backed; no in-memory variant of this builder).
        if (owner.equals("net.openhft.chronicle.queue.impl.single.SingleChronicleQueueBuilder")
                && method.equals("build")) return Effect.FS;
        // LangChain4j — CHAT models are always a remote API → generate/chat → Net. embed() is NOT keyed:
        // EmbeddingModel can be an in-process (onnx) model, so leave it ambiguous (no fabrication).
        if (owner.startsWith("dev.langchain4j.model.")
                && (method.equals("generate") || method.equals("chat"))) return Effect.NET;
        // Memcached (xmemcached; spymemcached already modeled) + Aerospike → Net.
        if (owner.equals("net.rubyeye.xmemcached.XMemcachedClient")
                && (method.equals("get") || method.equals("set") || method.equals("delete")
                    || method.equals("add") || method.equals("replace") || method.equals("incr")
                    || method.equals("decr") || method.equals("append") || method.equals("prepend"))) return Effect.NET;
        // Discord JDA — RestAction.queue/complete/submit is the wire send; the restaction.* builder subtypes
        // inherit them, so key the requests package + the action verbs.
        if (owner.startsWith("net.dv8tion.jda.api.requests.")
                && (method.equals("queue") || method.equals("complete") || method.equals("submit")
                    || method.equals("queueAfter") || method.equals("submitAfter"))) return Effect.NET;
        // Mailgun (sargue) → Net.
        if (owner.equals("net.sargue.mailgun.Mail") && method.equals("send")) return Effect.NET;
        if (owner.equals("spark.Spark") && method.equals("init")) return Effect.NET;
        // ffmpeg wrapper — *.run forks the ffmpeg/ffprobe binary → Exec.
        if (owner.startsWith("net.bramp.ffmpeg.") && method.equals("run")) return Effect.EXEC;
        // ML — ONNX Runtime createSession(String|path) loads the model off disk → Fs (createSession(byte[])
        // is in-memory → pure); OrtSession.run is opaque native inference → Unknown (can't see into native).
        if (owner.equals("ai.onnxruntime.OrtEnvironment") && method.equals("createSession")
                && desc != null && desc.startsWith("(Ljava/lang/String;")) return Effect.FS;
        if (owner.equals("ai.onnxruntime.OrtSession") && method.equals("run")) return Effect.UNKNOWN;
        // Stanford CoreNLP — the pipeline ctor loads serialized models off disk/classpath → Fs.
        if (owner.equals("edu.stanford.nlp.pipeline.StanfordCoreNLP") && method.equals("<init>")) return Effect.FS;
        // ── JVM-language stdlibs + JSF (batch 19) — κ-covered prefixes, unmodeled = FLOOR-DROPPED silent ──
        // Groovy SQL — the high-level GDK groovy.sql.Sql is the API apps call (candor modeled only the
        // lower-level org.codehaus.groovy.runtime helpers). All its query verbs open a Connection + run a
        // Statement → Db.
        if (owner.equals("groovy.sql.Sql")) {
            switch (method) {
                case "execute": case "executeInsert": case "executeUpdate": case "rows": case "firstRow":
                case "eachRow": case "query": case "call": case "callWithRows": case "withBatch":
                    return Effect.DB;
                default: break;
            }
        }
        // Groovy XML/JSON slurpers — parse(File|Path) opens the file → Fs, parse(URL) fetches → Net
        // (descriptor-gated; parseText/parse(Reader|InputStream|byte[]) are in-memory/caller-stream → pure).
        if ((owner.equals("groovy.xml.XmlSlurper") || owner.equals("groovy.xml.XmlParser")
                || owner.equals("groovy.util.XmlSlurper") || owner.equals("groovy.util.XmlParser")
                || owner.equals("groovy.json.JsonSlurper"))
                && method.equals("parse") && desc != null) {
            if (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")) return Effect.FS;
            if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
        }
        // kotlinx-io filesystem — candor models kotlin.io/kotlin.io.path but NOT the newer kotlinx.io.files
        // .FileSystem. Its source/sink/delete/etc. hit the disk → Fs (resolve/Path-ctor are path algebra → pure).
        if (owner.equals("kotlinx.io.files.FileSystem")) {
            switch (method) {
                case "source": case "sink": case "delete": case "createDirectories": case "atomicMove":
                case "list": case "metadataOrNull":
                    return Effect.FS;
                default: break;
            }
        }
        // Kotlin stdlib file API (kotlin.io FilesKt extensions on java.io.File; kotlin.io.path PathsKt
        // on java.nio.file.Path) — Kotlin's IDIOMATIC filesystem surface, compiled to static calls on
        // these owners. VERB-level, not owner-level: both classes also hold pure path manipulation
        // (relativeTo/normalize/resolve/name accessors), which must stay pure. The stat family
        // (exists/isDirectory/fileSize) is Fs, mirroring the Rust engine's std::path::Path rule. (Found
        // by a Kotlin-idiom probe: `f.readText()` was silent-pure — masked at first by the java.io.File
        // owner-match catching the File CTOR in the same fn.) `$default` wrappers share the base name.
        if (owner.equals("kotlin.io.FilesKt") || owner.equals("kotlin.io.TextStreamsKt")
                || owner.equals("kotlin.io.path.PathsKt")) {
            // A URL-receiver read (`URL.readText()/readBytes()` — TextStreamsKt) is NETWORK egress, not
            // filesystem: the verb-prefix below would mislabel it Fs (a wrong effect, worse than an
            // under-report). The descriptor's first parameter is the receiver. (Found by /code-review max.)
            if (desc != null && desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
            String base = method.endsWith("$default") ? method.substring(0, method.length() - 8) : method;
            if (base.startsWith("read") || base.startsWith("write") || base.startsWith("append")
                    || base.startsWith("copy") || base.startsWith("delete") || base.startsWith("create")
                    || base.startsWith("walk") || base.startsWith("forEach") || base.startsWith("use")
                    || base.startsWith("list") || base.equals("exists") || base.equals("notExists")
                    || base.equals("isDirectory") || base.equals("isRegularFile")
                    || base.equals("isSymbolicLink") || base.equals("fileSize") || base.equals("moveTo")
                    || base.equals("inputStream") || base.equals("outputStream")
                    || base.equals("reader") || base.equals("writer")
                    || base.equals("bufferedReader") || base.equals("bufferedWriter")
                    || base.equals("printWriter") || base.equals("getLastModifiedTime")
                    || base.equals("setLastModifiedTime"))
                return Effect.FS;
            return null; // Path()/div/name/relativeTo/normalize — pure path manipulation
        }
        // Kotlin stdlib entropy (kotlin.random.Random / Random.Default / top-level RandomKt) — Kotlin's
        // idiomatic randomness; whole-owner, mirroring the java.util.Random handling.
        if (owner.equals("kotlin.random.Random") || owner.equals("kotlin.random.Random$Default")
                || owner.equals("kotlin.random.RandomKt"))
            return Effect.RAND;
        // Kotlin stdlib collection/range/array entropy verbs — `list.random()` / `(1..6).random()` /
        // `arr.random()` / `list.shuffled()` draw entropy inside the stdlib body (candor doesn't descend
        // into kotlin-stdlib), so the VERB must be classified, like kotlin.random.Random above. Verb-gated
        // (these owners have hundreds of pure methods → NOT whole-owner).
        if ((owner.equals("kotlin.collections.CollectionsKt") || owner.equals("kotlin.ranges.RangesKt")
                || owner.equals("kotlin.collections.ArraysKt"))
                && (method.equals("random") || method.equals("randomOrNull") || method.equals("shuffled")
                    || method.equals("shuffle")))
            return Effect.RAND;
        // Scala stdlib I/O — the language's own stdlib. scala.io.Source file/URL reads; scala.sys.process
        // subprocess spawn (`cmd.!` / `.run` compile to $bang / run on the process owners).
        if (owner.equals("scala.io.Source$") || owner.equals("scala.io.Source")) {
            if (method.equals("fromFile") || method.equals("fromPath") || method.equals("fromResource")) return Effect.FS;
            if (method.equals("fromURL") || method.equals("fromURI")) return Effect.NET;
            return null;
        }
        if (owner.startsWith("scala.sys.process")
                && (method.equals("run") || method.startsWith("$bang") || method.startsWith("lazyLines")
                    || method.startsWith("lineStream")))
            return Effect.EXEC;
        // HTTP / cloud-storage clients — the CONCRETE-class ubiquitous ones (parallel to the already-modeled
        // RestTemplate/WebClient/Jedis; a pinned concrete receiver resolved to pure → silent-pure). Verb-gated
        // so request/URL BUILDERS stay pure (no fabrication).
        if ((owner.equals("okhttp3.Call") || owner.equals("okhttp3.RealCall"))
                && (method.equals("execute") || method.equals("enqueue"))) return Effect.NET;
        if (owner.equals("retrofit2.Call") && (method.equals("execute") || method.equals("enqueue"))) return Effect.NET;
        // okhttp WebSocket — the wire verbs (Call.execute/enqueue above is the HTTP path; the WS path is
        // distinct and was silent-pure). send/close transmit; the factory opens the connection.
        if (owner.equals("okhttp3.WebSocket") && (method.equals("send") || method.equals("close"))) return Effect.NET;
        // okio — the I/O substrate okhttp routes ALL its socket + disk-cache traffic through (the coverage
        // differential's #1 disclosed package: 953 invisible okio calls in one okhttp scan). okio is MIXED
        // and must be modeled PRECISELY at the CONSTRUCTION BOUNDARY, not on the buffered read/write:
        //   • `okio.Buffer` is an in-memory byte buffer — writeUtf8/writeByte/size/read* are PURE (it
        //     dominates okhttp's okio usage by call count). A whole-owner okio rule would FABRICATE Fs/Net
        //     on every Buffer op (the cardinal sin) — so Buffer is NOT modeled at all.
        //   • `okio.BufferedSink`/`okio.BufferedSource` are the AMBIGUOUS layer: a BufferedSink may wrap a
        //     Buffer (pure) OR a socket/file Sink (I/O), and the two are INDISTINGUISHABLE at the bytecode
        //     level. So their read/write/flush stay DISCLOSED (unmodeled), not classified — modeling them
        //     would fabricate on the in-memory case.
        //   • The effect boundary is the `okio.Okio` static FACTORY that opens the real resource. Verified
        //     against okhttp's bytecode: it calls Okio.source/sink(Socket) (the TLS+plain socket path) and
        //     Okio.source/appendingSink(File) (the disk cache). DESCRIPTOR-GATED on the receiver param:
        //     Socket → Net, File/Path → Fs. The InputStream/OutputStream overloads wrap a CALLER-supplied
        //     stream (the Fs/Net is on that stream's own owner, caught at its construction) → stay pure;
        //     `buffer(Source)`/`buffer(Sink)`/`blackhole()` are pure wrappers/no-ops → stay pure.
        if (owner.equals("okio.Okio") && desc != null) {
            if ((method.equals("source") || method.equals("sink") || method.equals("appendingSink"))
                    && desc.startsWith("(Ljava/net/Socket;")) return Effect.NET;
            if ((method.equals("source") || method.equals("sink") || method.equals("appendingSink"))
                    && (desc.startsWith("(Ljava/io/File;") || desc.startsWith("(Ljava/nio/file/Path;")))
                return Effect.FS;
            // buffer/blackhole and the (InputStream)/(OutputStream) overloads fall through → pure.
        }
        // okio.FileSystem — okio 3's filesystem abstraction (the multiplatform java.nio.file.Files analog).
        // Its read/write/sink/source/appendingSink/delete/createDirectory/createDirectories/list/listOrNull/
        // metadata/atomicMove/copy/openReadOnly/openReadWrite/deleteRecursively/createSymlink hit the live FS
        // → Fs. The dispatch lands on okio.FileSystem (abstract) or the concrete JvmSystemFileSystem/
        // NioSystemFileSystem. Verb-gated so the pure surface (canonicalize is path math; exists/metadataOrNull
        // ALSO stat the FS, kept Fs) doesn't over-match — these names don't collide with a pure okio method.
        if ((owner.equals("okio.FileSystem") || owner.equals("okio.JvmSystemFileSystem")
                || owner.equals("okio.NioSystemFileSystem"))
                && (method.equals("read") || method.equals("write") || method.equals("source")
                    || method.equals("sink") || method.equals("appendingSink") || method.equals("delete")
                    || method.equals("deleteRecursively") || method.equals("createDirectory")
                    || method.equals("createDirectories") || method.equals("list") || method.equals("listOrNull")
                    || method.equals("listRecursively") || method.equals("metadata")
                    || method.equals("metadataOrNull") || method.equals("exists") || method.equals("atomicMove")
                    || method.equals("copy") || method.equals("openReadOnly") || method.equals("openReadWrite")
                    || method.equals("createSymlink")))
            return Effect.FS;
        // Reactor-Netty — get/post/put configure the client (immutable builder, pure); the `response*`
        // terminals execute and consume the wire.
        if (owner.equals("reactor.netty.http.client.HttpClient")
                && (method.equals("response") || method.equals("responseContent") || method.equals("responseSingle")
                    || method.equals("responseConnection"))) return Effect.NET;
        // ['com', 'misc'] shared rule — see sharedAwsSdkClients below
        Effect s65 = sharedAwsSdkClients(owner, method, desc);
        if (s65 != null) return s65;
        // ['misc', 'org'] shared rule — see sharedKvStoreClients below
        Effect s66 = sharedKvStoreClients(owner, method, desc);
        if (s66 != null) return s66;
        // ── Android SDK (candor scans the pre-dex JVM bytecode) — the android.* effect surface was entirely
        // unmodeled (silent-pure, often not even Unknown for concrete owners). The high-frequency mappings:
        if (owner.equals("android.database.sqlite.SQLiteDatabase")    // local SQLite DB ops
                && (method.equals("query") || method.equals("rawQuery") || method.equals("insert")
                    || method.equals("update") || method.equals("delete") || method.startsWith("execSQL")
                    || method.startsWith("insertOrThrow") || method.equals("replace")))
            return Effect.DB;
        if (owner.equals("android.database.sqlite.SQLiteOpenHelper")
                && (method.equals("getWritableDatabase") || method.equals("getReadableDatabase"))) return Effect.DB;
        // ContentResolver is a Binder RPC to another app's ContentProvider → Ipc (cross-app data access).
        if (owner.equals("android.content.ContentResolver")
                && (method.equals("query") || method.equals("insert") || method.equals("update")
                    || method.equals("delete") || method.startsWith("openInputStream")
                    || method.startsWith("openOutputStream") || method.startsWith("openFileDescriptor")
                    || method.equals("call") || method.startsWith("bulkInsert")))
            return Effect.IPC;
        if (owner.equals("android.webkit.WebView")
                && (method.equals("loadUrl") || method.equals("postUrl") || method.startsWith("loadData"))) return Effect.NET;
        // Settings.{System,Secure,Global}.getString/putString — ambient system settings / device-id reads.
        // EXACT owner + EXACT method (was startsWith, which fabricated Env on the NameValueCache inner
        // class's getStringHelper/getIntForCache — found by a fabrication sweep).
        if ((owner.equals("android.provider.Settings$System") || owner.equals("android.provider.Settings$Secure")
                || owner.equals("android.provider.Settings$Global"))
                && (method.equals("getString") || method.equals("putString") || method.equals("getInt")
                    || method.equals("putInt") || method.equals("getLong") || method.equals("putLong")
                    || method.equals("getFloat") || method.equals("putFloat"))) return Effect.ENV;
        if ((owner.equals("android.content.ClipboardManager") || owner.equals("android.text.ClipboardManager"))
                && !isConventionallyPure(method))
            return Effect.CLIPBOARD;
        // SharedPreferences.Editor.commit/apply writes the prefs XML file; Context.openFile* opens app-private files.
        if (owner.equals("android.content.SharedPreferences$Editor")
                && (method.equals("commit") || method.equals("apply"))) return Effect.FS;
        // bucket continues (bytecode-size chunking, a TAIL call: fall-through only —
        // an early `return null` pure-exit above returns through the dispatcher untouched)
        return classifyOtherTail(owner, method, desc);
    }

    private static Effect classifyOtherTail(String owner, String method, String desc) {
        if (owner.equals("android.content.Context")
                && (method.equals("openFileInput") || method.equals("openFileOutput")
                    || method.equals("getFilesDir") || method.equals("getCacheDir")
                    || method.equals("deleteFile"))) return Effect.FS;
        // Context component-launch is Binder IPC to other app components.
        if (owner.equals("android.content.Context")
                && (method.equals("startActivity") || method.equals("startService")
                    || method.equals("startForegroundService") || method.equals("sendBroadcast")
                    || method.equals("bindService"))) return Effect.IPC;
        // ['com', 'java', 'javax', 'misc', 'org'] shared rule — see sharedJdbcStatements below
        Effect s67 = sharedJdbcStatements(owner, method, desc);
        if (s67 != null) return s67;
        // ['com', 'io', 'jakarta', 'java', 'javax', 'misc', 'org'] shared rule — see sharedPanacheQueryTerminals below
        Effect s68 = sharedPanacheQueryTerminals(owner, method, desc);
        if (s68 != null) return s68;
        // AWS v2 credentials — RESOLUTION reads the environment/profile chain; factories are pure.
        if (owner.startsWith("software.amazon.awssdk.auth.credentials")
                && method.startsWith("resolveCredentials")) return Effect.ENV;
        // ['java', 'misc', 'org'] shared rule — see sharedLoggingFacades below
        if (isLoggingFacadesOwner(owner)) return sharedLoggingFacades(owner, method, desc);
        // JavaFX clipboard (the AWT successor) — getSystemClipboard hands out the handle; setContent/
        // getString/getContent/hasString read/write it. Verb-gated so the pure quartet stays pure.
        if (owner.equals("javafx.scene.input.Clipboard")
                && !isConventionallyPure(method)
                && (method.equals("getSystemClipboard") || method.startsWith("get") || method.startsWith("set")
                    || method.startsWith("has") || method.equals("clear")))
            return Effect.CLIPBOARD;
        return null;
    }

    // ── shared rules: owners spanning several dispatch buckets — defined ONCE, called from each
    //    bucket at the original cascade position. A null return means 'no match, keep cascading'
    //    (none of these carries an early pure-exit; the logging facade block, which does, is
    //    split into an owner GATE + an always-returning body instead).
    private static Effect sharedSocketAndWireClients(String owner, String method, String desc) {
        if (owner.equals("java.net.Socket") || owner.equals("java.net.ServerSocket")
                || owner.equals("java.net.DatagramSocket")
                // MulticastSocket extends DatagramSocket; a receiver TYPED as MulticastSocket emits
                // invokevirtual owner=java/net/MulticastSocket for the inherited send/receive, which the
                // exact-owner match above misses — a silent Net under-report (multicast send/receive IS
                // network I/O). joinGroup/leaveGroup likewise.
                || owner.equals("java.net.MulticastSocket")
                || owner.equals("java.nio.channels.SocketChannel")
                || owner.equals("java.nio.channels.ServerSocketChannel")
                || owner.equals("java.nio.channels.DatagramChannel")
                || owner.equals("java.nio.channels.AsynchronousSocketChannel")
                || owner.equals("java.nio.channels.AsynchronousServerSocketChannel")
                // java.net.http: ONLY HttpClient.send/sendAsync touch the wire. The old blanket
                // `java.net.http.` prefix FABRICATED Net on the entire pure builder/factory surface —
                // `HttpRequest.newBuilder()…build()`, `HttpClient.newBuilder()`, BodyHandlers/BodyPublishers —
                // none of which transmit (the cardinal sin: Net on a provably-pure request builder; found by
                // a Net-deep sweep). Mirror the ktor verb-precision below: the send verbs are the one
                // dispatch boundary that performs I/O; everything else in the package is request
                // construction and stays pure.
                || (owner.equals("java.net.http.HttpClient")
                    && (method.equals("send") || method.equals("sendAsync")))
                // java.net.http.WebSocket: the wire verbs (sendText/sendBinary/sendPing/sendPong/sendClose/
                // request) transmit, and Builder.buildAsync OPENS the connection. The 0.5.15 narrowing of
                // the blanket `java.net.http.` prefix to HttpClient.send fixed a builder FABRICATION but
                // REGRESSED the whole WebSocket API to silent-pure — restore it verb-precisely. The pure
                // `HttpClient.newWebSocketBuilder()` factory stays pure (no `build` verb here).
                || (owner.equals("java.net.http.WebSocket") && method.startsWith("send"))
                || (owner.equals("java.net.http.WebSocket") && method.equals("request"))
                || (owner.equals("java.net.http.WebSocket$Builder") && method.equals("buildAsync"))
                // TLS sockets: SSLSocket extends java.net.Socket, so a receiver typed SSLSocket emits
                // owner=javax/net/ssl/SSLSocket for the inherited getInputStream/getOutputStream and for
                // startHandshake — missed by the exact java.net.Socket match (same shape as MulticastSocket,
                // silent TLS I/O). The factories open the connection.
                || owner.equals("javax.net.ssl.SSLSocket")
                || (owner.equals("javax.net.ssl.SSLSocketFactory") && method.equals("createSocket"))
                || (owner.equals("javax.net.SocketFactory") && method.equals("createSocket"))
                // Conscrypt TLS sockets (Google's BoringSSL-backed JSSE provider — the dominant alternative
                // SSLSocket backend, ubiquitous on Android + gRPC). The concrete socket impls all extend
                // javax.net.ssl.SSLSocket, so a receiver typed as the INTERFACE already hits the rule above;
                // these add the case where the receiver is statically typed as the concrete Conscrypt class
                // (Conscrypt.newSocket / Android), which emits owner=org/conscrypt/* for the inherited socket
                // I/O — otherwise silent. VERB-gated to the wire boundary (startHandshake + the stream
                // getters); the inherited pure getters (getSession/getApplicationProtocol/…) stay pure — a
                // whole-owner rule would fabricate on them. (BouncyCastle/OpenJSSE rejected: their impls are
                // package-private — never a usefully-typed receiver — and the public surface a real okhttp
                // scan actually calls is pure config: BCSSLSocket.get/setParameters, Conscrypt.isAvailable.)
                || (owner.startsWith("org.conscrypt.") && owner.endsWith("Socket")
                    && (method.equals("startHandshake") || method.equals("getInputStream")
                        || method.equals("getOutputStream")))
                || ((owner.equals("org.conscrypt.OpenSSLSocketImpl")
                        || owner.equals("org.conscrypt.AbstractConscryptSocket"))
                    && (method.equals("startHandshake") || method.equals("getInputStream")
                        || method.equals("getOutputStream")))
                || owner.equals("org.springframework.web.client.RestTemplate")
                || owner.equals("org.springframework.web.client.RestClient")
                || owner.startsWith("org.springframework.web.reactive.function.client.")
                // ktor client (Kotlin's dominant HTTP client): the request verbs (get/post/request —
                // INLINE suspend extensions) all funnel through `HttpStatement.execute`, the one
                // dispatch boundary the compiler actually emits (ktor's reqwest-send analog); `body`
                // on the statement also executes. The response readers (`bodyAsText`/`bodyAsChannel`
                // on HttpResponseKt, `body` on HttpClientCallKt) consume the wire. Builders
                // (HttpRequestBuilder/url/setMethod) and HttpClient() construction stay pure. (Found
                // by a ktor-consumer probe: fetch/post/request all silent-pure.)
                || (owner.equals("io.ktor.client.statement.HttpStatement")
                    && (method.startsWith("execute") || method.startsWith("body")))
                || (owner.equals("io.ktor.client.statement.HttpResponseKt")
                    && (method.startsWith("body") || method.startsWith("read")))
                || (owner.equals("io.ktor.client.call.HttpClientCallKt") && method.startsWith("body"))
                // DNS resolution — getByName/getAllByName/getLocalHost/getCanonicalHostName send a query
                // to the resolver (UDP/TCP) = network egress. getByAddress(byte[]) builds from bytes with
                // NO lookup, so it's excluded. (Found by a controlled JDK-effect probe: all three lookup
                // forms read Net 0 — a silent under-report on an extremely common API.)
                || (owner.equals("java.net.InetAddress")
                    && (method.equals("getByName") || method.equals("getAllByName")
                        || method.equals("getLocalHost") || method.equals("getCanonicalHostName")))
                || (owner.equals("java.net.URL")
                    && (method.equals("openStream") || method.equals("openConnection") || method.equals("getContent")))
                // URLConnection / HttpURLConnection wire verbs: `URL.openConnection()` returns a LAZY
                // connection that performs NO I/O until a wire verb runs — and that verb is very commonly in
                // a DIFFERENT method than the openConnection() call (open in a helper, read the body in
                // another), so classifying only openConnection left the actual transmission silent-pure
                // (found by a Net-deep sweep). connect()/getInputStream()/getOutputStream()/getContent()/
                // getResponseCode()/getResponseMessage() each trigger the request; the pure getters
                // (getURL/getRequestMethod/setRequestProperty) stay unclassified — no fabrication.
                || ((owner.equals("java.net.URLConnection") || owner.equals("java.net.HttpURLConnection")
                        || owner.equals("javax.net.ssl.HttpsURLConnection"))
                    && (method.equals("connect") || method.equals("getInputStream")
                        || method.equals("getOutputStream") || method.equals("getContent")
                        || method.equals("getResponseCode") || method.equals("getResponseMessage")))
                // JNDI — a naming/directory lookup contacts a remote naming service (LDAP/RMI/DNS/CORBA);
                // `InitialContext.lookup("ldap://…")` is exactly the hidden network egress an effect checker
                // exists to surface (the Log4Shell vector). The lookup/bind/search family is the boundary;
                // Name/NameParser data types stay pure. (Found by a controlled JDK probe — was Net 0.)
                || (owner.startsWith("javax.naming.")
                    && (method.equals("lookup") || method.equals("lookupLink") || method.equals("doLookup")
                        || method.equals("bind") || method.equals("rebind") || method.equals("rename")
                        || method.equals("list") || method.equals("listBindings") || method.equals("search")
                        || method.equals("createSubcontext") || method.equals("destroySubcontext")
                        || method.equals("getAttributes") || method.equals("modifyAttributes")))
                // RMI — the registry/Naming facade resolves and invokes remote objects over the network.
                || owner.equals("java.rmi.Naming")
                || owner.equals("java.rmi.registry.Registry")
                || owner.equals("java.rmi.registry.LocateRegistry")
                // The JDK's built-in HTTP server binds a listening socket (create/bind) and serves it.
                || (owner.equals("com.sun.net.httpserver.HttpServer")
                    && (method.equals("create") || method.equals("bind") || method.equals("start")))
                // The per-request HttpExchange I/O surface (batch-20 — FLOOR-dropped silent under com.sun.*):
                // sendResponseHeaders writes to the client socket; get{Request,Response}Body obtain the
                // socket-backed streams (the only attachable point, like servletGetWriter). PURE NOT touched:
                // getRequestHeaders/getRequestURI (in-memory parsed request).
                || (owner.equals("com.sun.net.httpserver.HttpExchange")
                    && (method.equals("sendResponseHeaders") || method.equals("getResponseBody")
                        || method.equals("getRequestBody")))
                // SimpleFileServer.createFileServer binds the server socket (+ serves files off disk).
                || (owner.equals("com.sun.net.httpserver.SimpleFileServer") && method.equals("createFileServer"))
                // JMX remote — JMXConnectorFactory.connect opens a remote management channel (RMI/JMXMP);
                // JMXConnector.getMBeanServerConnection materializes it. Same remote-channel shape as RMI/JNDI.
                || (owner.equals("javax.management.remote.JMXConnectorFactory") && method.equals("connect"))
                || (owner.equals("javax.management.remote.JMXConnector")
                    && (method.equals("connect") || method.equals("getMBeanServerConnection"))))
            return Effect.NET;
        return null;
    }

    private static Effect sharedJdbcStatements(String owner, String method, String desc) {
        // Database — JDBC, Spring JdbcTemplate, JPA EntityManager (Spring Data repos handled in analyze)
        if ((owner.equals("java.sql.Statement") || owner.equals("java.sql.PreparedStatement")
                || owner.equals("java.sql.CallableStatement") || owner.equals("java.sql.Connection")
                || owner.equals("java.sql.DriverManager")
                // javax.sql.DataSource.getConnection — the POOLED-connection acquisition every HikariCP/
                // Tomcat-JDBC/Spring DataSource app uses (interface dispatch lands on this owner); missed
                // by the java.sql-only list, so the standard connection entry point read silent-pure.
                || owner.equals("javax.sql.DataSource") || owner.equals("javax.sql.CommonDataSource")
                // Concrete connection-pool DataSources: a receiver typed as the concrete pool emits its OWN
                // owner for getConnection (interface dispatch on javax.sql.DataSource is only seen when the
                // receiver is typed as the interface). The dominant pools — without these a `HikariDataSource
                // ds; ds.getConnection()` read silent-pure.
                || owner.equals("com.zaxxer.hikari.HikariDataSource")
                || owner.equals("org.apache.tomcat.jdbc.pool.DataSource")
                || owner.equals("org.apache.commons.dbcp2.BasicDataSource")
                || owner.equals("org.apache.commons.dbcp.BasicDataSource")
                || owner.equals("com.mchange.v2.c3p0.ComboPooledDataSource")
                || owner.equals("com.alibaba.druid.pool.DruidDataSource")
                || owner.equals("oracle.jdbc.pool.OracleDataSource")
                || owner.equals("oracle.ucp.jdbc.PoolDataSource")
                || owner.equals("org.postgresql.ds.PGSimpleDataSource")
                || owner.equals("org.h2.jdbcx.JdbcDataSource")
                || owner.equals("org.springframework.jdbc.datasource.DriverManagerDataSource"))
                && (method.startsWith("execute") || method.equals("getConnection")
                    || method.equals("prepareStatement") || method.equals("prepareCall")
                    // Connection.isValid pings the server (a real round-trip the execute*-only gate missed).
                    || method.equals("isValid")
                    // commit/rollback finalize the transaction at the server (a real round-trip);
                    // setAutoCommit(false) begins one — all DB I/O the execute*-only gate missed.
                    || method.equals("commit") || method.equals("rollback") || method.equals("setAutoCommit")
                    // setSavepoint/releaseSavepoint issue a real server command (SAVEPOINT/RELEASE), the
                    // same transaction-control round-trip as commit — batch-16 FLOOR-suppressed silent.
                    || method.equals("setSavepoint") || method.equals("releaseSavepoint")
                    // setTransactionIsolation commonly issues SET TRANSACTION ISOLATION LEVEL at the server
                    // (batch-17). (nativeSQL is spec-defined LOCAL string translation → left unmodeled, no
                    // fabrication on the common local case.)
                    || method.equals("setTransactionIsolation")))
            return Effect.DB;
        return null;
    }

    private static Effect sharedResultSet(String owner, String method, String desc) {
        // ResultSet is a LIVE DB CURSOR: cursor-movement verbs fetch rows from the server (a round-trip in
        // streaming/forward-only mode), updatable-set writes flush to the DB, and refreshRow re-reads. The
        // scalar getXxx reads of the CURRENT row are in-memory, so they stay pure (no fabrication — Db on a
        // cursor-advance is sound). Covers java.sql.ResultSet + RowSet (javax.sql).
        if ((owner.equals("java.sql.ResultSet") || owner.startsWith("javax.sql.") && owner.endsWith("RowSet"))
                && (method.equals("next") || method.equals("previous") || method.equals("first")
                    || method.equals("last") || method.equals("absolute") || method.equals("relative")
                    || method.equals("refreshRow") || method.equals("insertRow") || method.equals("updateRow")
                    || method.equals("deleteRow")))
            return Effect.DB;
        return null;
    }

    private static Effect sharedPanacheQueryTerminals(String owner, String method, String desc) {
        // Quarkus Panache PanacheQuery — the query object returned by an entity/repository `find(…)`. Only the
        // TERMINAL result verbs execute; page/range/withLock/project/filter are pure builders. (The entity-side
        // active-record `find`/`list`/… are handled at the call site in Candor.analyze via extendsPanacheEntity;
        // this closes a PanacheQuery terminated in a DIFFERENT method than the find.) Covers the hibernate-orm,
        // reactive, and mongodb Panache variants (all name the type PanacheQuery under a .panache. package).
        if (owner.contains(".panache.") && owner.endsWith("PanacheQuery")) {
            switch (method) {
                case "list": case "stream": case "firstResult": case "firstResultOptional":
                case "singleResult": case "singleResultOptional": case "count":
                    return Effect.DB;
                default: break;
            }
        }
        return null;
    }

    /** The owner gate of sharedLoggingFacades — hoisted so each bucket's call site is one line. */
    private static boolean isLoggingFacadesOwner(String owner) {
        return owner.startsWith("org.slf4j.") || owner.startsWith("java.util.logging.")
                || owner.startsWith("org.apache.logging.log4j.") || owner.startsWith("ch.qos.logback.")
                // commons-logging (JCL) — the 5th facade, still everywhere in legacy enterprise code
                // (a real 2,257-class Struts app: 791 JCL calls). Emit verbs are the shared six
                // (trace/debug/info/warn/error/fatal — already in isLogEmitVerb); LogFactory.getLog and
                // Log.isXxxEnabled fall through to pure. (κ batch 28.)
                || owner.startsWith("org.apache.commons.logging.")
                // java.lang.System.Logger — the JDK 9+ platform logging facade (libraries use it to avoid a
                // logging-framework dep). Was absent → a `System.Logger.log(...)` read silent-pure while the
                // SAME call via java.util.logging was Log (a κ-coverage inconsistency, not by design). The
                // emit verb `log` is already in isLogEmitVerb; isLoggable/getName fall through to pure.
                || owner.equals("java.lang.System$Logger");
    }

    private static Effect sharedLoggingFacades(String owner, String method, String desc) {
            // RESOURCE-OPENING handlers/appenders are NOT just Log — they open a file/socket/DB connection
            // (the ctor) and transmit (publish/append) to it. A network log handler is a real exfil channel;
            // a file handler does Fs; a DB appender does Db. The package gate below would `return null`
            // (silent-pure) for these. Verb-gated (ctor + the transmit/lifecycle verbs) so the inherited
            // config getters (getLevel/getFormatter/…) stay pure — no fabrication. (Found by a fresh
            // classify-gate review; the soundness fuzzer's Log form only exercises Logger.info.)
            boolean opensResource = method.equals("<init>") || method.equals("publish") || method.equals("append")
                    || method.equals("doAppend") || method.equals("start") || method.equals("flush")
                    || method.equals("close") || method.equals("openFile") || method.equals("setFile");
            if (opensResource) {
                if (owner.equals("java.util.logging.SocketHandler")
                        || owner.endsWith(".SocketAppender") || owner.endsWith(".SSLSocketAppender")
                        || owner.endsWith(".SyslogAppender") || owner.endsWith(".KafkaAppender")
                        || owner.endsWith(".SmtpAppender") || owner.endsWith(".HttpAppender"))
                    return Effect.NET;
                if (owner.equals("java.util.logging.FileHandler")
                        || owner.endsWith(".FileAppender") || owner.endsWith(".RollingFileAppender")
                        || owner.endsWith(".RollingRandomAccessFileAppender") || owner.endsWith(".RandomAccessFileAppender"))
                    return Effect.FS;
                if (owner.endsWith(".DBAppender") || owner.endsWith(".JDBCAppender")
                        || owner.endsWith(".JPAAppender") || owner.endsWith(".CassandraAppender"))
                    return Effect.DB;
            }
            if (isLogEmitVerb(method)) return Effect.LOG;
            return null;
    }

    private static Effect sharedDocumentBuilder(String owner, String method, String desc) {
        if ((owner.equals("javax.xml.parsers.DocumentBuilder") || owner.equals("javax.xml.parsers.SAXParser")
                || owner.equals("org.xml.sax.XMLReader")) && method.equals("parse"))
            return Effect.UNKNOWN;
        return null;
    }

    private static Effect sharedServletResponse(String owner, String method, String desc) {
        // ── jakarta/javax EE WEB surfaces (batch 17) — κ-covered prefixes, so unmodeled = FLOOR-DROPPED
        //    silent. These are the most common server-side APIs in the JVM; a controller writing an HTTP
        //    response / a JAX-RS client call / a websocket push all read silent-pure without these rules. ──
        // Servlet response → Net (sends bytes to the client). sendError/sendRedirect/flushBuffer commit the
        // response; getWriter/getOutputStream obtain the client sink (the only attachable point — the writes
        // go through generic java.io the engine can't pin to Net). PURE siblings NOT touched: setStatus/
        // setHeader/addHeader/setContentType (in-memory header buffer), ServletRequest.getParameter.
        if ((owner.equals("jakarta.servlet.ServletResponse") || owner.equals("javax.servlet.ServletResponse")
                || owner.equals("jakarta.servlet.http.HttpServletResponse")
                || owner.equals("javax.servlet.http.HttpServletResponse"))
                && (method.equals("sendError") || method.equals("sendRedirect") || method.equals("flushBuffer")
                    || method.equals("getWriter") || method.equals("getOutputStream"))) return Effect.NET;
        return null;
    }

    private static Effect sharedInvocationBuilder(String owner, String method, String desc) {
        // JAX-RS client — the SyncInvoker terminal (get/post/put/delete/method) does the HTTP round-trip →
        // Net. PURE builders NOT touched: Client.target / WebTarget.request / WebTarget.path.
        if ((owner.equals("jakarta.ws.rs.client.SyncInvoker") || owner.equals("javax.ws.rs.client.SyncInvoker")
                || owner.equals("jakarta.ws.rs.client.Invocation$Builder")
                || owner.equals("javax.ws.rs.client.Invocation$Builder"))
                && (method.equals("get") || method.equals("post") || method.equals("put")
                    || method.equals("delete") || method.equals("method") || method.equals("head")
                    || method.equals("options") || method.equals("trace"))) return Effect.NET;
        return null;
    }

    private static Effect sharedRemoteEndpointAsync(String owner, String method, String desc) {
        // WebSocket RemoteEndpoint — send* pushes a frame over the socket → Net. PURE accessor NOT touched:
        // Session.getBasicRemote/getAsyncRemote (return the endpoint).
        if ((owner.equals("jakarta.websocket.RemoteEndpoint$Basic") || owner.equals("javax.websocket.RemoteEndpoint$Basic")
                || owner.equals("jakarta.websocket.RemoteEndpoint$Async") || owner.equals("javax.websocket.RemoteEndpoint$Async"))
                && (method.equals("sendText") || method.equals("sendBinary") || method.equals("sendObject")
                    || method.equals("sendPing") || method.equals("sendPong"))) return Effect.NET;
        return null;
    }

    private static Effect sharedMarshaller(String owner, String method, String desc) {
        // JAXB — Marshaller.marshal(File)/Unmarshaller.unmarshal(File) touch disk → Fs; unmarshal(URL) → Net
        // (descriptor-gated; the OutputStream/Writer/InputStream overloads are caller-stream → pure).
        if ((owner.equals("jakarta.xml.bind.Marshaller") || owner.equals("javax.xml.bind.Marshaller"))
                && method.equals("marshal") && desc != null && desc.contains("Ljava/io/File;")) return Effect.FS;
        return null;
    }

    private static Effect sharedUnmarshaller(String owner, String method, String desc) {
        if ((owner.equals("jakarta.xml.bind.Unmarshaller") || owner.equals("javax.xml.bind.Unmarshaller"))
                && method.equals("unmarshal") && desc != null) {
            if (desc.startsWith("(Ljava/io/File;")) return Effect.FS;
            if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
        }
        return null;
    }

    private static Effect sharedTransaction(String owner, String method, String desc) {
        // ── Remaining jakarta/javax EE (batch 18) — κ-covered, unmodeled = FLOOR-DROPPED silent ──
        // JTA transactions → Db — the @Transactional / app-server transaction BOUNDARY (begin opens, commit
        // flushes+COMMITs the enlisted resources, rollback issues ROLLBACK). PURE siblings NOT touched:
        // getStatus/setRollbackOnly/setTransactionTimeout (local txn state, no resource-manager round-trip).
        if ((owner.equals("jakarta.transaction.UserTransaction") || owner.equals("javax.transaction.UserTransaction")
                || owner.equals("jakarta.transaction.Transaction") || owner.equals("javax.transaction.Transaction")
                || owner.equals("jakarta.transaction.TransactionManager") || owner.equals("javax.transaction.TransactionManager"))
                && (method.equals("begin") || method.equals("commit") || method.equals("rollback"))) return Effect.DB;
        return null;
    }

    private static Effect sharedDispatch(String owner, String method, String desc) {
        // JAX-WS — Dispatch.invoke* performs the SOAP wire send → Net. PURE NOT touched: Service.getPort
        // (returns a proxy), Service.createDispatch (builds the object).
        if ((owner.equals("jakarta.xml.ws.Dispatch") || owner.equals("javax.xml.ws.Dispatch"))
                && method.startsWith("invoke")) return Effect.NET;
        return null;
    }

    private static Effect sharedService(String owner, String method, String desc) {
        // jakarta.mail — Service.connect is the shared super of Store/Transport.connect (already Net) that
        // candor missed by keying only the subclasses; Folder.expunge removes \Deleted on the IMAP server.
        if ((owner.equals("jakarta.mail.Service") || owner.equals("javax.mail.Service")) && method.equals("connect"))
            return Effect.NET;
        return null;
    }

    private static Effect sharedFolder(String owner, String method, String desc) {
        if ((owner.equals("jakarta.mail.Folder") || owner.equals("javax.mail.Folder")) && method.equals("expunge"))
            return Effect.NET;
        return null;
    }

    private static Effect sharedConnection(String owner, String method, String desc) {
        // JMS lifecycle/browse → Net: Connection.start/stop (begin/halt broker delivery); QueueBrowser
        // .getEnumeration (browses the broker queue — a round-trip). PURE NOT touched: createSession,
        // QueueBrowser.getQueue.
        if ((owner.equals("jakarta.jms.Connection") || owner.equals("javax.jms.Connection"))
                && (method.equals("start") || method.equals("stop"))) return Effect.NET;
        return null;
    }

    private static Effect sharedQueueBrowser(String owner, String method, String desc) {
        if ((owner.equals("jakarta.jms.QueueBrowser") || owner.equals("javax.jms.QueueBrowser"))
                && method.equals("getEnumeration")) return Effect.NET;
        return null;
    }

    private static Effect sharedExternalContext(String owner, String method, String desc) {
        // JSF — ExternalContext.redirect (HTTP 302) / dispatch (server forward) drive the servlet response →
        // Net. PURE NOT touched: encodeRedirectURL/encodeActionURL (string rewriting), the request-map getters.
        if ((owner.equals("jakarta.faces.context.ExternalContext") || owner.equals("javax.faces.context.ExternalContext"))
                && (method.equals("redirect") || method.equals("dispatch"))) return Effect.NET;
        return null;
    }

    private static Effect sharedMessagingTemplates(String owner, String method, String desc) {
        // Messaging (Net-family) — Spring templates + the RAW broker/mail clients (as ubiquitous as the
        // templates that were already modeled; each was silent-pure, not even Unknown, because a pinned
        // concrete receiver resolved to an unmodeled owner). Message BUILDERS (MimeMessage.setText,
        // ProducerRecord ctor, TextMessage.setText) stay pure — only the send/connect/fetch verbs are Net.
        if (owner.equals("org.springframework.jms.core.JmsTemplate")
                || owner.equals("org.springframework.kafka.core.KafkaTemplate")
                || owner.equals("org.springframework.amqp.rabbit.core.RabbitTemplate")
                // JavaMail / Jakarta Mail — SMTP send + IMAP/POP connect & fetch
                || ((owner.equals("javax.mail.Transport") || owner.equals("jakarta.mail.Transport"))
                    && (method.equals("send") || method.equals("sendMessage") || method.equals("connect")))
                || ((owner.equals("javax.mail.Store") || owner.equals("jakarta.mail.Store")
                        || owner.equals("javax.mail.Folder") || owner.equals("jakarta.mail.Folder"))
                    && (method.equals("connect") || method.equals("open") || method.startsWith("getMessage")
                        || method.equals("fetch")))
                // raw Kafka producer/consumer
                || (owner.equals("org.apache.kafka.clients.producer.KafkaProducer")
                    && (method.equals("send") || method.equals("flush")))
                || (owner.equals("org.apache.kafka.clients.consumer.KafkaConsumer")
                    && (method.equals("poll") || method.startsWith("commit")))
                // raw JMS producer/consumer
                || ((owner.equals("javax.jms.MessageProducer") || owner.equals("jakarta.jms.MessageProducer"))
                    && method.equals("send"))
                || ((owner.equals("javax.jms.MessageConsumer") || owner.equals("jakarta.jms.MessageConsumer"))
                    && (method.equals("receive") || method.startsWith("receive")))
                // JMS transacted-session commit/rollback flush produced msgs + ack consumed ones to the
                // broker (a wire round-trip); recover redelivers. The transaction TERMINAL (batch-16 silent).
                || ((owner.equals("javax.jms.Session") || owner.equals("jakarta.jms.Session")
                        || owner.equals("javax.jms.JMSContext") || owner.equals("jakarta.jms.JMSContext"))
                    && (method.equals("commit") || method.equals("rollback") || method.equals("recover")))
                // RabbitMQ AMQP wire
                || (owner.equals("com.rabbitmq.client.Channel")
                    && (method.equals("basicPublish") || method.equals("basicGet") || method.equals("basicConsume")))
                || (owner.equals("com.rabbitmq.client.ConnectionFactory") && method.equals("newConnection"))
                // MQTT / NATS / Pulsar / ZeroMQ
                || (owner.equals("org.eclipse.paho.client.mqttv3.MqttClient")
                    && (method.equals("publish") || method.equals("connect") || method.equals("subscribe")))
                || (owner.equals("io.nats.client.Connection")
                    && (method.equals("publish") || method.equals("request") || method.equals("requestWithTimeout")))
                || (owner.equals("org.apache.pulsar.client.api.Producer") && method.equals("send"))
                // Spring WebSocket send (java.net.http.WebSocket.send* is already Net — parity)
                || (owner.equals("org.springframework.web.socket.WebSocketSession") && method.equals("sendMessage")))
            return Effect.NET;
        return null;
    }

    private static Effect sharedEntityManager(String owner, String method, String desc) {
        // JPA EntityManager — the whole-owner rule FABRICATED Db on its pure surface: `createQuery`/
        // `createNamedQuery`/`createNativeQuery` BUILD a Query (no execution), and `clear`/`detach`/
        // `getCriteriaBuilder`/`contains` are in-memory persistence-context ops touching no DB (cardinal
        // sin; found by a Db-deep sweep). Gate to the methods that actually round-trip: find/getReference
        // (SELECT), persist/merge/remove/refresh (the unit-of-work DB ops), flush (forces the SQL), lock.
        if ((owner.equals("jakarta.persistence.EntityManager") || owner.equals("javax.persistence.EntityManager"))
                && (method.equals("find") || method.equals("getReference") || method.equals("persist")
                    || method.equals("merge") || method.equals("remove") || method.equals("refresh")
                    || method.equals("flush") || method.equals("lock")))
            return Effect.DB;
        return null;
    }

    private static Effect sharedEntityTransaction(String owner, String method, String desc) {
        // JPA EntityTransaction.commit FLUSHES the persistence context to the DB (the buffered INSERT/UPDATE/
        // DELETE + COMMIT) and rollback issues ROLLBACK — the transaction TERMINAL where writes durably land
        // (em.getTransaction().commit() is a ubiquitous idiom). Was FLOOR-suppressed silent (batch-16).
        if ((owner.equals("jakarta.persistence.EntityTransaction") || owner.equals("javax.persistence.EntityTransaction"))
                && (method.equals("commit") || method.equals("rollback"))) return Effect.DB;
        return null;
    }

    private static Effect sharedQuery(String owner, String method, String desc) {
        // JPA query EXECUTION verbs — `em.createQuery(hql)` is a pure BUILDER (above), but the round-trip is
        // on the returned Query/TypedQuery/StoredProcedureQuery. Without classifying these, the whole JPA
        // query path (createQuery + getResultList in one method) read pure (Unknown if unpinned, fully
        // silent-pure if the Query receiver was monomorphically pinned). getResultStream also executes.
        if ((owner.equals("jakarta.persistence.Query") || owner.equals("javax.persistence.Query")
                || owner.equals("jakarta.persistence.TypedQuery") || owner.equals("javax.persistence.TypedQuery")
                || owner.equals("jakarta.persistence.StoredProcedureQuery")
                || owner.equals("javax.persistence.StoredProcedureQuery"))
                && (method.equals("getResultList") || method.equals("getSingleResult")
                    || method.equals("getResultStream") || method.equals("executeUpdate")
                    || method.equals("execute")))
            return Effect.DB;
        return null;
    }

    private static Effect sharedIMap(String owner, String method, String desc) {
        // ── More library effect leaves (found silent-pure by the library κ-coverage probe, batch 7) ──
        // Distributed caches/data grids — get/put/etc. are CLUSTER round-trips → Net. OWNER-scoped to the
        // cache interfaces (Hazelcast IMap / Ignite IgniteCache / Infinispan BasicCache+Cache). IMap and
        // BasicCache EXTEND java.util.concurrent.ConcurrentMap, so we must NOT key java.util.Map — a Map-typed
        // receiver stays pure (anchors mapGetPure/concurrentMapGetPure). Verb set = data ops; local accessors
        // (getName/getLocalMapStats) stay pure.
        if (owner.equals("com.hazelcast.map.IMap") || owner.equals("org.apache.ignite.IgniteCache")
                || owner.equals("org.infinispan.commons.api.BasicCache") || owner.equals("org.infinispan.Cache")) {
            switch (method) {
                case "get": case "getAll": case "getAsync": case "put": case "putAll": case "putAsync":
                case "putIfAbsent": case "set": case "setAsync": case "remove": case "removeAll":
                case "removeAsync": case "delete": case "replace": case "merge": case "compute":
                case "computeIfAbsent": case "computeIfPresent": case "containsKey": case "containsValue":
                case "clear": case "loadAll": case "keySet": case "values": case "entrySet":
                case "size": case "isEmpty":
                    return Effect.NET;
                default: break;
            }
        }
        return null;
    }

    private static Effect sharedLogical(String owner, String method, String desc) {
        // HashiCorp Vault — Spring VaultTemplate + vault-java-driver Logical do the secrets round-trip → Net.
        // (VaultTemplate is otherwise FLOOR-SUPPRESSED as an org.springframework.* κ-covered prefix —
        // modeling it explicitly here surfaces the real Net leaf the floor was hiding.)
        if ((owner.equals("org.springframework.vault.core.VaultTemplate")
                || owner.equals("org.springframework.vault.core.VaultKeyValueOperations")
                || owner.equals("io.github.jopenlibs.vault.api.Logical"))
                && (method.equals("read") || method.equals("write") || method.equals("list")
                    || method.equals("delete"))) return Effect.NET;
        return null;
    }

    private static Effect sharedJavalin(String owner, String method, String desc) {
        // ── More library effect leaves (batch 14 — precision: these were already INVISIBLE-DISCLOSED=sound;
        //    modeled to upgrade the disclosure to the concrete effect) ──────────────────────────────────
        // HTTP/stream SERVER frameworks — start()/init() binds a listening socket → Net (a different leaf
        // shape than the many HTTP *clients*; the route-registration / config methods stay pure).
        if ((owner.equals("io.javalin.Javalin") || owner.equals("io.undertow.Undertow")
                || owner.equals("org.eclipse.jetty.server.Server")
                || owner.equals("org.apache.kafka.streams.KafkaStreams"))
                && method.equals("start")) return Effect.NET;
        return null;
    }

    private static Effect sharedKvStoreClients(String owner, String method, String desc) {
        // Distributed caches / KV stores — RAW concrete clients (interface-typed Lettuce/Hazelcast/Ignite/
        // Ehcache/JCache correctly fall to the Unknown dispatch-floor; in-process Caffeine/Guava stay pure —
        // so this is ONLY the concrete remote clients that silently resolved to pure).
        // Shared pure-surface exemption (else a fabrication on toString/hashCode/equals and the cached
        // field-reads getDB/getSessionId/getState/getSessionTimeout/isConnected/isBroken — fabrication
        // sweeps; these touch no command, no round-trip). The remaining methods are commands.
        boolean kvPure = isConventionallyPure(method)
                || method.equals("getDB") || method.equals("getSessionId") || method.equals("getState")
                || method.equals("getSessionTimeout") || method.equals("isConnected") || method.equals("isBroken");
        // Jedis/JedisCluster ARE Redis → Db (the Redis labelling reconciliation; all Redis clients carry Db,
        // matching RedisTemplate + Lettuce/Redisson/Spring-Data-Redis above + candor-ts's redis→Db).
        if ((owner.equals("redis.clients.jedis.Jedis") || owner.equals("redis.clients.jedis.JedisCluster"))
                && !kvPure) return Effect.DB;
        // Memcached (a remote cache) + ZooKeeper (a coordination service) are NOT Redis and NOT part of the
        // Redis decision → Net (remote round-trip), as before. (Whether a remote KV cache should be Db is a
        // separate labelling question, left as-is.)
        if ((owner.equals("net.spy.memcached.MemcachedClient") || owner.equals("org.apache.zookeeper.ZooKeeper"))
                && !kvPure) return Effect.NET;
        return null;
    }

    private static Effect sharedBlobAsyncClient(String owner, String method, String desc) {
        // Cloud object-store clients — entirely remote (every method is an HTTP round-trip to the store) →
        // whole-owner Net, like the modeled AWS S3. Object-protocol excluded.
        if ((owner.equals("io.minio.MinioClient") || owner.equals("io.minio.MinioAsyncClient")
                || owner.equals("com.google.cloud.storage.Storage")
                || owner.equals("com.azure.storage.blob.BlobClient")
                || owner.equals("com.azure.storage.blob.BlobClientBase")
                || owner.equals("com.azure.storage.blob.BlobAsyncClient"))
                && !isConventionallyPure(method)) return Effect.NET;
        return null;
    }

    private static Effect sharedAwsSdkClients(String owner, String method, String desc) {
        // The v1 SDK's request-making types are the *Client classes AND the service INTERFACES
        // (AmazonS3/AmazonSQS/AWSLambda — the recommended way to type a client variable; a call through
        // the interface emits the interface owner, which the Client-suffix gate MISSED: a real
        // `AmazonS3.copyObject` read silent-invisible — found live, uflexi dogfood). Interfaces are the
        // Amazon*/AWS* simple names OUTSIDE .model./.builder types; TransferManager is the S3 high-level
        // I/O front (upload/download/copy do the transfers).
        // OWNER GATE: the *Client classes only. Batch 30b widened this to the Amazon*/AWS*-named service
        // interfaces + TransferManager to catch interface-typed calls (AmazonS3.copyObject) — but that
        // FABRICATED Net on same-named PURE value types (AmazonS3URI.getBucket, a URI parser) and, paired
        // with a com.amazonaws coverage grant, SILENCED unmodeled facades (DynamoDBMapper.save). Reverted:
        // an interface-typed AWS request that this rule misses discloses `invisible` (com.amazonaws is NOT
        // κ-covered), the honest floor — never fabrication, never silent-pure. (review 0.8.3 regression.)
        if ((owner.startsWith("software.amazon.awssdk.services.") || owner.startsWith("com.amazonaws.services."))
                && owner.endsWith("Client")
                && (method.startsWith("get") || method.startsWith("put") || method.startsWith("list")
                    || method.startsWith("create") || method.startsWith("delete") || method.startsWith("send")
                    || method.startsWith("query") || method.startsWith("scan") || method.startsWith("update")
                    || method.startsWith("describe") || method.startsWith("invoke") || method.startsWith("upload")
                    || method.startsWith("download") || method.startsWith("receive") || method.startsWith("publish")
                    // KMS / crypto service verbs — over-HTTP calls that the original verb list missed
                    // (batch-6: KmsClient.encrypt read silent-pure). decrypt/sign/verify/reEncrypt/generate*.
                    || method.startsWith("encrypt") || method.startsWith("decrypt") || method.startsWith("sign")
                    || method.startsWith("verify") || method.startsWith("reEncrypt")
                    // copy* — S3 copyObject/copyPart make server-side-copy requests; missed by the
                    // original verb list (found live: the uflexi dogfood's S3 archival path).
                    || method.startsWith("copy")
                    || method.startsWith("generate"))
                && !isConventionallyPure(method)
                // AWS v1 CLIENT classes themselves carry pure config getters that match `get*` but make
                // no request: getRegion/getRegionName/getSignerRegion/getResourceUrl/getUrl/
                // getCachedResponseMetadata, etc. The 0.5.21 `owner.endsWith("Client")` gate stopped the
                // v1 *model* getters fabricating, but the client's OWN config getters still matched get* →
                // FABRICATED Net on a provably-pure accessor (cardinal sin, regression). Carve them out by
                // exact name. getBucketRegionViaHeadRequest is NOT here → stays Net (it does a HEAD).
                && !isAwsPureClientGetter(method)) return Effect.NET;
        return null;
    }

}
