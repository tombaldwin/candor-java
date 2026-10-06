package io.poly.candor;

import io.poly.candor.model.Effect;

import java.util.List;

/**
 * SOUNDNESS R814 (with R812 folded in) — JDK members that really perform an effect and that the κ table did
 * not charge, so the covered-prefix grant ({@code Rules.KAPPA_COVERED_PREFIXES}: {@code java}, {@code javax},
 * {@code jdk}, {@code com.sun}, …) certified them PURE.
 *
 * <p><b>R812 is one instance.</b> A two-argument {@code new File(lit, child)} IS masked at every charged use;
 * it went silent only when the value reached a sink the classifier did not charge {@code Fs}. EXECUTED:
 * {@code new ProcessBuilder(..).redirectOutput(new File("/tmp/benign", child)).start()} wrote outside
 * {@code /tmp/benign} and {@code allow Fs … /tmp/benign} exited 0, on the unit and on its caller.
 *
 * <p><b>HOW THE MEMBERS WERE FOUND — mechanically, not from memory, and the boundary is stated:</b>
 * <ol>
 *   <li><b>E1, by descriptor.</b> Every public/protected member of every public type in every UNQUALIFIED-
 *       EXPORTED package of the JDK 21 image (227 packages, 44,195 members) that takes, or is invoked on, a
 *       locator type — {@code File}, {@code Path}, {@code FileDescriptor}, {@code URI}, {@code URL}: 532 members.
 *       Each was asked of the ENGINE (a synthetic consumer calling it, scanned) rather than of the κ table,
 *       so co-emitted charges count. 320 were uncharged; every one was decided (javadoc / JDK source /
 *       execution), and the effectful ones are below.</li>
 *   <li><b>E2, by body reach.</b> A JDK-internal call graph (static targets; virtual calls expanded only
 *       into NON-exported implementations) seeded with every call the classifier itself charges and with
 *       the I/O natives, joined against the 824-jar corpus' call sites. Its residue is dominated by the
 *       JDK reading its OWN installation (logging.properties, jaxp.properties, provider-JAR verification,
 *       krb5.conf once per JVM) and by class loading — the same class of read the classifier deliberately
 *       leaves uncharged for {@code ResourceBundle}/{@code ServiceLoader} lookups — plus socket OPTION
 *       accessors, which {@code Candor.isPureHandleAccessor} carves out on purpose. What it found that E1
 *       could not (no locator in the descriptor): the ImageIO stream-cache writes, {@code isReachable},
 *       the RMI export/socket-factory surface, the JMX connector server, {@code Collections.shuffle}.</li>
 *   <li><b>A descriptor pass for {@code Rand}</b> over members taking {@code Random}/{@code SecureRandom}/
 *       {@code RandomGenerator} (40 members).</li>
 * </ol>
 * Ground truth for every in-call charge is an EXECUTED oracle — a {@code SecurityManager}
 * ({@code -Djava.security.manager=allow}) recording the {@code checkRead/checkWrite/checkDelete/
 * checkConnect/checkListen} the JDK makes before each syscall — calibrated on controls that must stay
 * silent ({@code ProcessBuilder.directory}, {@code Path.toFile}, {@code UnixDomainSocketAddress.of},
 * a {@code file:} {@code URL.equals}, {@code ImageIO.read} with {@code setUseCache(false)}).
 *
 * <p><b>TWO KINDS OF CHARGE, said as such.</b> Most members perform the effect INSIDE the call (a stat, an
 * open, a temp file, a listen, a DNS query). A few only ARM it: they store a locator that a LATER terminal
 * opens — {@code Redirect.to(File)}/{@code redirectOutput(File)} (the file is opened by {@code start()},
 * EXECUTED), {@code BodyHandlers.ofFile} (written during {@code HttpClient.send}), {@code KeyTab.getInstance
 * (File)} (read by {@code exists()}/{@code getKeys}). They are charged at the arm for the reason SPEC §1
 * ⟨0.32⟩ gives for {@code Exec}: the terminal does not carry the locator, so charging only the terminal
 * would leave the destination unjudgeable — a benign sibling literal would certify it, which is R812.
 *
 * <p><b>WHAT IS DELIBERATELY NOT HERE</b> — each a stated class, not an omission:
 * {@code URI}/{@code URL}/{@code Path} algebra and accessors; value/parameter objects that only carry a
 * locator to a terminal that is ALREADY charged ({@code CodeSource}, {@code URIParameter},
 * {@code PreparedStatement.setURL}, {@code HttpRequest.newBuilder(URI)}); {@code ProcessBuilder.directory}
 * and {@code Runtime.exec(..., File)} (a working directory, executed: no syscall); interfaces with no JDK
 * implementation ({@code AppletContext}, {@code java.rmi.server.LoaderHandler}); the JDK's own one-time
 * configuration reads (above); CLOCK/RAND reads that are INCIDENTAL to a member whose purpose is something
 * else (a {@code LogRecord}/{@code Notification} timestamp, {@code SimpleDateFormat}'s two-digit-year
 * century, {@code createTempFile}'s random name, the Monte-Carlo witnesses of {@code isProbablePrime});
 * and the crypto operations whose output is randomized only for SOME algorithms ({@code Cipher.doFinal},
 * {@code Signature.sign}) — a descriptor cannot tell which, so the honest answer there is a hedge, which is
 * a different direction and a different price. The counts are in the R814 commit message for the κ-grant
 * restructuring lane (R492/R727).
 */
final class KappaJdkSinks {
    private KappaJdkSinks() {}

    private static boolean takes(String desc, String type) { return desc != null && desc.contains(type); }
    private static final String FILE = "Ljava/io/File;", PATH = "Ljava/nio/file/Path;", URL = "Ljava/net/URL;";

    /** The κ answer for a member no earlier rule matched. Called LAST in each bucket, so it can only turn a
     *  {@code null} into an effect — it cannot change any answer the table already gave. */
    static Effect charge(String owner, String method, String desc) {
        switch (owner) {
            // ── Fs: opens / stats / temp-files INSIDE the call (all EXECUTED) ──────────────────────────
            case "java.awt.Font":
                // createFont(int,File)/createFonts(File): canRead() then read. The InputStream forms copy the
                // stream into a TEMP FILE first (Font.java: Files.createTempFile("+~JF", ".tmp")).
                if (method.equals("createFont") || method.equals("createFonts")) return Effect.FS;
                return null;
            case "java.security.KeyStore":
                return method.equals("getInstance") && takes(desc, FILE) ? Effect.FS : null;   // new FileInputStream(file)
            case "java.security.KeyStore$Builder":
                return method.equals("newInstance") && takes(desc, FILE) ? Effect.FS : null;   // file.isFile() + probe
            case "javax.imageio.stream.FileImageInputStream":
            case "javax.imageio.stream.FileImageOutputStream":
            case "javax.imageio.stream.FileCacheImageInputStream":
            case "javax.imageio.stream.FileCacheImageOutputStream":
                // The ctor opens the file / creates the cache temp file; the stream verbs are file I/O on it,
                // including the readInt/writeShort/... family an exact-typed receiver inherits.
                if (method.equals("<init>")) return (owner.contains("Cache") || takes(desc, FILE)) ? Effect.FS : null;
                return isStreamIoVerb(method) ? Effect.FS : null;
            case "javax.imageio.ImageIO":
                // setCacheDirectory stats the directory. read(InputStream)/write(..,OutputStream)/
                // createImage{In,Out}putStream build a FileCacheImage*Stream whenever useCache is on (the
                // default): a temp file under the cache directory. EXECUTED; control setUseCache(false) silent.
                if (method.equals("setCacheDirectory") || method.equals("createImageInputStream")
                        || method.equals("createImageOutputStream")) return Effect.FS;
                if (method.equals("read") && desc.startsWith("(Ljava/io/InputStream;")) return Effect.FS;
                if (method.equals("write") && desc.endsWith("Ljava/io/OutputStream;)Z")) return Effect.FS;
                return null;
            case "javax.imageio.spi.ImageInputStreamSpi":
                return method.equals("createInputStreamInstance") ? Effect.FS : null;
            case "javax.imageio.spi.ImageOutputStreamSpi":
                return method.equals("createOutputStreamInstance") ? Effect.FS : null;
            case "javax.sound.midi.MidiSystem":
            case "javax.sound.midi.spi.MidiFileReader":
            case "javax.sound.midi.spi.MidiFileWriter":
            case "javax.sound.midi.spi.SoundbankReader":
            case "javax.sound.sampled.AudioSystem":
            case "javax.sound.sampled.spi.AudioFileReader":
            case "javax.sound.sampled.spi.AudioFileWriter":
                // The File overloads read/write that file; the URL overloads fetch it (URL -> Net, the label
                // the existing ImageIO/AudioSystem URL rules already use). InputStream overloads stay pure-relative.
                if (takes(desc, FILE)) return Effect.FS;
                if (takes(desc, URL) && !method.equals("<init>")) return Effect.NET;
                return null;
            case "javax.xml.validation.SchemaFactory":
                if (method.equals("newSchema") && takes(desc, FILE)) return Effect.FS;
                if (method.equals("newSchema") && takes(desc, URL)) return Effect.NET;
                return null;
            case "javax.xml.transform.stream.StreamSource":
            case "javax.xml.transform.stream.StreamResult":
                // setSystemId(File) is f.toURI() — a stat (the File.toURI rule) — and the Transformer then
                // reads/writes exactly that file while its own charge is Unknown, never Fs.
                return (method.equals("<init>") || method.equals("setSystemId")) && takes(desc, FILE) ? Effect.FS : null;
            case "jdk.jfr.Configuration":
                return method.equals("create") && takes(desc, PATH) ? Effect.FS : null;
            case "jdk.jfr.Recording":
            case "jdk.jfr.consumer.RecordingStream":
            case "jdk.management.jfr.RemoteRecordingStream":
                // dump(Path) writes; Recording.setDestination(Path) creates the file at once (EXECUTED);
                // RemoteRecordingStream(conn, dir) Files.exists(dir) and downloads into it.
                if (method.equals("dump") || method.equals("setDestination")) return takes(desc, PATH) ? Effect.FS : null;
                return method.equals("<init>") && takes(desc, PATH) ? Effect.FS : null;
            case "jdk.jfr.consumer.EventStream":
                return method.equals("openFile") || method.equals("openRepository") ? Effect.FS : null;
            case "jdk.jfr.consumer.RecordingFile":
                // A recording-file HANDLE: the ctor opens, the read verbs read it.
                return method.equals("<init>") || method.equals("write") || method.equals("readAllEvents")
                        || method.equals("readEvent") || method.equals("hasMoreEvents")
                        || method.equals("readEventTypes") || method.equals("close") ? Effect.FS : null;
            case "com.sun.net.httpserver.SimpleFileServer":
                return method.equals("createFileHandler") ? Effect.FS : null;   // stats the root, then serves it
            case "java.net.http.HttpRequest$BodyPublishers":
                return method.equals("ofFile") ? Effect.FS : null;              // stats/opens now, reads at send
            case "java.net.http.HttpResponse$BodyHandlers":
            case "java.net.http.HttpResponse$BodySubscribers":
                // ARM: the response body is written to this path during HttpClient.send, which is charged
                // Net only. ofFileDownload also stats/writes-checks the directory now (EXECUTED).
                return method.startsWith("ofFile") ? Effect.FS : null;
            case "java.lang.ProcessBuilder$Redirect":
                // ARM: ProcessBuilder.start() opens this file (EXECUTED: the write lands at start()).
                return (method.equals("from") || method.equals("to") || method.equals("appendTo"))
                        && takes(desc, FILE) ? Effect.FS : null;
            case "java.nio.file.spi.FileTypeDetector":
                return method.equals("probeContentType") ? Effect.FS : null;    // the SPI under Files.probeContentType
            case "javax.security.auth.kerberos.KeyTab":
                // getInstance/getUnboundInstance ARM a keytab file; exists()/getKeys() read it (EXECUTED).
                return method.equals("getInstance") || method.equals("getUnboundInstance")
                        || method.equals("exists") || method.equals("getKeys") ? Effect.FS : null;
            case "javax.swing.filechooser.FileSystemView":
                // EXECUTED over every public member: a DENYLIST of the ones proven to touch nothing for any
                // argument; the rest stat, list, or mkdir (createNewFolder), some only for a ShellFolder
                // argument — which is what getFiles() hands back, so they are charged.
                return isPureFileSystemViewMember(method) ? null : Effect.FS;
            case "javax.swing.JFileChooser":
                // EXECUTED: these list or stat the current directory in the call itself. The property
                // setters that only trigger the UI's background rescan are not charged (see the class doc).
                return method.equals("<init>") || method.equals("setup") || method.equals("setCurrentDirectory")
                        || method.equals("changeToParentDirectory") || method.equals("rescanCurrentDirectory")
                        || method.equals("isTraversable") || method.equals("getTypeDescription")
                        || method.equals("ensureFileIsVisible") || method.equals("setSelectedFiles")
                        || method.equals("showDialog") || method.equals("showOpenDialog")
                        || method.equals("showSaveDialog") ? Effect.FS : null;
            case "javax.swing.plaf.basic.BasicDirectoryModel":
                return method.equals("renameFile") ? Effect.FS : null;          // oldFile.renameTo(newFile)
            case "javax.swing.plaf.basic.BasicFileChooserUI$BasicFileView":
                return method.equals("getName") || method.equals("getTypeDescription") || method.equals("getIcon")
                        ? Effect.FS : null;                                       // via FileSystemView
            case "javax.swing.ImageIcon":
                if (!method.equals("<init>")) return null;
                if (desc.startsWith("(Ljava/lang/String;")) return Effect.FS;   // Toolkit.getImage(filename) + wait
                if (desc.startsWith("(Ljava/net/URL;")) return Effect.NET;
                return null;
            case "java.awt.Toolkit":
                if (!method.equals("getImage") && !method.equals("createImage")) return null;
                if (desc.startsWith("(Ljava/lang/String;)")) return Effect.FS;  // a filename
                if (desc.startsWith("(Ljava/net/URL;)")) return Effect.NET;
                return null;
            case "javax.activation.FileDataSource":
            case "jakarta.activation.FileDataSource":
                // Not JDK, but under the same javax/jakarta grant and in the measured corpus reach: the ctor
                // ARMS a file that getInputStream/getOutputStream open (a mail Transport.send reads it).
                return method.equals("<init>") || method.equals("getInputStream") || method.equals("getOutputStream")
                        ? Effect.FS : null;
            case "com.sun.security.auth.login.ConfigFile":
                // ()/refresh() read the login configuration named by java.security.auth.login.config or
                // ~/.java.login.config; (URI) reads that URI (URL label, as above).
                if (method.equals("<init>") && takes(desc, "Ljava/net/URI;")) return Effect.NET;
                return method.equals("<init>") || method.equals("refresh") ? Effect.FS : null;

            // ── Net ─────────────────────────────────────────────────────────────────────────────────────
            case "java.net.URL":
                // equals/hashCode/sameFile RESOLVE the host (URLStreamHandler.hostsEqual -> getHostAddress ->
                // InetAddress.getByName); the javadoc says so: "Since hosts comparison requires name resolution,
                // this operation is a blocking operation." EXECUTED: checkConnect(host,-1); a file: URL is silent.
                // §4's conventionally-pure carve-out covers DISPATCH over Object, and MUST NOT extend to where an
                // effect hides — this is the one place in the JDK it does.
                return (method.equals("equals") && desc.equals("(Ljava/lang/Object;)Z"))
                        || (method.equals("hashCode") && desc.equals("()I"))
                        || method.equals("sameFile") ? Effect.NET : null;
            case "java.net.URLStreamHandler":
                return method.equals("equals") || method.equals("hashCode") || method.equals("sameFile")
                        || method.equals("hostsEqual") || method.equals("getHostAddress") ? Effect.NET : null;
            case "java.net.InetAddress":
            case "java.net.Inet4Address":
            case "java.net.Inet6Address":
                // ICMP ECHO, else a TCP connect to port 7 (javadoc). Not visible to a SecurityManager.
                return method.equals("isReachable") ? Effect.NET : null;
            case "java.rmi.server.UnicastRemoteObject":
                // EXPORTING listens on a TCP port (EXECUTED: checkListen); unexport closes it. The protected
                // ctors export `this`, so a subclass's super() call is a listen.
                return method.equals("<init>") || method.equals("exportObject") || method.equals("unexportObject")
                        ? Effect.NET : null;
            case "java.rmi.server.RMISocketFactory":
            case "java.rmi.server.RMIClientSocketFactory":
            case "java.rmi.server.RMIServerSocketFactory":
            case "javax.rmi.ssl.SslRMIClientSocketFactory":
            case "javax.rmi.ssl.SslRMIServerSocketFactory":
                // The RMI twins of javax.net.SocketFactory.createSocket, which is already Net (EXECUTED: connect).
                return method.equals("createSocket") || method.equals("createServerSocket") ? Effect.NET : null;
            case "javax.management.remote.JMXConnectorServer":
            case "javax.management.remote.JMXConnectorServerMBean":
            case "javax.management.remote.rmi.RMIConnectorServer":
                // start() exports the RMI server object (a listen) and binds it in JNDI; stop() unexports.
                return method.equals("start") || method.equals("stop") ? Effect.NET : null;
            case "javax.management.remote.JMXServiceURL":
                // (protocol, host, port[, path]) with host == null calls InetAddress.getLocalHost() (EXECUTED).
                return method.equals("<init>") && desc.startsWith("(Ljava/lang/String;Ljava/lang/String;I")
                        ? Effect.NET : null;
            case "javax.management.loading.MLet":
            case "javax.management.loading.MLetMBean":
                return method.equals("getMBeansFromURL") ? Effect.NET : null;   // fetches the MLET file, then loads
            case "java.awt.SplashScreen":
                return method.equals("setImageURL") ? Effect.NET : null;        // url.openConnection(), reads it
            case "java.applet.Applet":
                return method.equals("newAudioClip") ? Effect.NET : null;       // reads the clip from the URL
            case "javax.swing.JEditorPane":
                // setPage(URL|String) / getStream(URL) open a URLConnection; the one-String ctor is setPage(url).
                if (method.equals("setPage") || method.equals("getStream")) return Effect.NET;
                if (method.equals("<init>") && (desc.equals("(Ljava/net/URL;)V") || desc.equals("(Ljava/lang/String;)V")))
                    return Effect.NET;
                return null;
            case "javax.swing.text.html.StyleSheet":
                return method.equals("importStyleSheet") ? Effect.NET : null;   // url.openStream()
            case "javax.swing.plaf.synth.SynthLookAndFeel":
                return method.equals("load") && takes(desc, URL) ? Effect.NET : null;

            // ── Exec: loading a native library runs its initialisers (the System.load rule's own reason) ──
            case "java.lang.foreign.SymbolLookup":
                return method.equals("libraryLookup") ? Effect.EXEC : null;

            // ── Unknown: an RMI codebase loader defines classes fetched from a URL (URLClassLoader's class) ──
            case "java.rmi.server.RMIClassLoader":
                // A row in UnknownReasonKindTableTest (whose census reads this file too): class loading is REFLECT.
                if (method.equals("loadClass") || method.equals("loadProxyClass")) return Effect.UNKNOWN;
                return null;

            // ── Rand: members whose PURPOSE is to draw entropy ──────────────────────────────────────────
            case "java.util.Collections":
                return method.equals("shuffle") ? Effect.RAND : null;           // "a default source of randomness"
            case "java.math.BigInteger":
                // draws from the Random it is handed — the same draw `rnd.nextInt()` is charged Rand for.
                return (method.equals("<init>") && takes(desc, "Ljava/util/Random;"))
                        || method.equals("probablePrime") ? Effect.RAND : null;
            case "javax.crypto.KEM$Encapsulator":
                return method.equals("encapsulate") ? Effect.RAND : null;       // a fresh random shared secret
            case "java.security.AlgorithmParameterGenerator":
                return method.equals("generateParameters") ? Effect.RAND : null;
            default:
                return null;
        }
    }

    /** Effects a call carries BESIDE the one {@code Classifier.classify} names — {@code classify} has a single
     *  slot, and each of these already answers something else there ({@code Exec}, {@code Net}). Routed by
     *  {@code Candor.handleMethodInsn} through the SAME two refiners as a classified effect, so the locator
     *  each one takes is judged by the Fs masking guards exactly as a classified Fs call's is. */
    static List<Effect> alsoCharges(String owner, String method, String desc) {
        switch (owner) {
            case "java.lang.ProcessBuilder":
                // R812: classify says Exec; the redirect FILE is opened by start() (EXECUTED) and named only here.
                return (method.equals("redirectInput") || method.equals("redirectOutput") || method.equals("redirectError"))
                        && desc.startsWith("(Ljava/io/File;)") ? FS_ONLY : List.of();
            case "java.awt.Desktop":
                // classify says Exec; each of these first stats the file (Desktop.checkFileValidation:
                // file.exists(), and canWrite()/isDirectory() for edit, the parent for browseFileDirectory).
                return (method.equals("open") || method.equals("edit") || method.equals("print")
                        || method.equals("browseFileDirectory")) && desc.startsWith("(Ljava/io/File;)") ? FS_ONLY : List.of();
            case "com.sun.net.httpserver.SimpleFileServer":
                // classify says Net (it binds); it also stats the root and serves files from it.
                return method.equals("createFileServer") ? FS_ONLY : List.of();
            default:
                return List.of();
        }
    }
    private static final List<Effect> FS_ONLY = List.of(Effect.FS);

    /** An Fs member some of whose destination NO File/Path operand names — a temp/cache file, a default
     *  directory, or a locator passed as {@code Object} or {@code File[]}. R409's descriptor read cannot see
     *  those, so without this a benign sibling literal would certify the call; the masking guard marks it
     *  instead, WHATEVER its typed operands say (a determined cache directory does not name the image input
     *  an SPI is handed as an {@code Object}). */
    static boolean fsUnnamedDestination(String owner, String method, String desc) {
        switch (owner) {
            case "javax.imageio.ImageIO":
                return (method.equals("read") && desc.startsWith("(Ljava/io/InputStream;"))
                        || (method.equals("write") && desc.endsWith("Ljava/io/OutputStream;)Z"))
                        || method.equals("createImageInputStream") || method.equals("createImageOutputStream");
            case "javax.imageio.spi.ImageInputStreamSpi":
            case "javax.imageio.spi.ImageOutputStreamSpi":
                return true;                              // the input/output is an Object (a File among others)
            case "java.awt.Font":
                return !namesAFileOperand(desc);          // the InputStream forms write a temp font file
            case "javax.swing.JFileChooser":
            case "javax.swing.filechooser.FileSystemView":
                // no-arg forms list a default/home directory; setSelectedFiles takes a File[]
                return !namesAFileOperand(desc) && !desc.startsWith("(Ljava/lang/String;");
            case "com.sun.security.auth.login.ConfigFile":
                return desc.startsWith("()");             // the login configuration named by a property / ~
            case "jdk.jfr.consumer.EventStream":
                return desc.startsWith("()");             // openRepository(): the JVM's own repository
            case "javax.security.auth.kerberos.KeyTab":
                return (method.equals("getInstance") || method.equals("getUnboundInstance"))
                        && !namesAFileOperand(desc);      // the default keytab
            default:
                return false;
        }
    }

    /** Whether some argument is EXACTLY a File or Path — the operands R409 reads. An array of them is not. */
    private static boolean namesAFileOperand(String desc) {
        for (org.objectweb.asm.Type t : org.objectweb.asm.Type.getArgumentTypes(desc)) {
            String d = t.getDescriptor();
            if (d.equals(FILE) || d.equals(PATH)) return true;
        }
        return false;
    }

    /** The I/O verbs of an ImageIO file-backed stream, by the ImageInputStream/ImageOutputStream naming
     *  contract: read*, write*, skip*, seek, length, flush*, reset, close. The pure position/bit/byte-order
     *  accessors (getStreamPosition, getBitOffset, setByteOrder, isCached*, mark) do not match. */
    private static boolean isStreamIoVerb(String m) {
        return m.startsWith("read") || m.startsWith("write") || m.startsWith("skip") || m.startsWith("flush")
                || m.equals("seek") || m.equals("length") || m.equals("reset") || m.equals("close");
    }

    /** FileSystemView members EXECUTED to touch nothing, for any argument — the denylist; every other
     *  member is charged. Pinned against the JDK's declared member set by {@code KappaJdkSinksTest}. */
    static boolean isPureFileSystemViewMember(String m) {
        switch (m) {
            case "<init>": case "getFileSystemView": case "createFileObject": case "createFileSystemRoot":
            case "isComputerNode": case "isDrive": case "isFloppyDrive": case "isFileSystemRoot":
            case "getHomeDirectory": case "getSystemTypeDescription":
            case "toString": case "hashCode": case "equals":
                return true;
            default:
                return false;
        }
    }
}
