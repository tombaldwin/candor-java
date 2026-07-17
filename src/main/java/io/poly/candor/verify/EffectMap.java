package io.poly.candor.verify;

import java.util.HashMap;
import java.util.Map;

/**
 * ⟨verify⟩ The oracle's OWN curated map from an effect-bearing JDK method (owner in internal form, e.g.
 * {@code java/nio/file/Files}, + method name) to a candor effect — or {@code null} for a call that is not
 * an observed effect boundary.
 *
 * <p>INDEPENDENCE: this deliberately does NOT import candor's {@code Rules}/{@code Classifier}. The oracle
 * checks the static engine against reality; if it borrowed the classifier's own opinion of "what is an
 * effect", a shared blind spot could hide on both sides. This map is hand-written from the JDK surface.
 *
 * <p>Precision over recall: a MISSED mapping just means that effect is never observed for that call — the
 * worst case is a disclosed-but-real effect going unwitnessed (the oracle stays silent), NEVER a false
 * violation. So the map is kept high-precision (only entry points that unambiguously perform the effect)
 * and it errs toward omission (e.g. {@code java/util/Random} is excluded as common + effectively pure PRNG
 * state; only {@code SecureRandom} — a real entropy draw — is mapped).
 */
final class EffectMap {

    private EffectMap() {}

    // key = owner (internal form) + "#" + methodName ; value = candor effect name.
    private static final Map<String, String> EXACT = new HashMap<>();
    // Owners whose EVERY effect-verb (by a name predicate) maps to one effect — used for the wide APIs
    // (java/nio/file/Files) where enumerating each overload is noise. Checked after EXACT.
    private static void fs(String owner, String method) { EXACT.put(owner + "#" + method, "Fs"); }
    private static void net(String owner, String method) { EXACT.put(owner + "#" + method, "Net"); }
    private static void exec(String owner, String method) { EXACT.put(owner + "#" + method, "Exec"); }
    private static void env(String owner, String method) { EXACT.put(owner + "#" + method, "Env"); }
    private static void clock(String owner, String method) { EXACT.put(owner + "#" + method, "Clock"); }
    private static void rand(String owner, String method) { EXACT.put(owner + "#" + method, "Rand"); }

    static {
        // ── Fs ─────────────────────────────────────────────────────────────────────────────────────
        fs("java/io/FileInputStream", "<init>");
        fs("java/io/FileOutputStream", "<init>");
        fs("java/io/FileReader", "<init>");
        fs("java/io/FileWriter", "<init>");
        fs("java/io/RandomAccessFile", "<init>");
        // java/nio/file/Files.* — the common read/write/enumerate surface (handled by name below too, but
        // list the headline verbs explicitly so an exact lookup is O(1) and self-documenting).
        for (String m : new String[] {
                "readAllBytes", "readAllLines", "readString", "newInputStream", "newOutputStream",
                "newBufferedReader", "newBufferedWriter", "write", "writeString", "delete",
                "deleteIfExists", "copy", "move", "createFile", "createDirectory", "createDirectories",
                "lines", "list", "walk", "newByteChannel",
        }) fs("java/nio/file/Files", m);

        // ── Net ────────────────────────────────────────────────────────────────────────────────────
        net("java/net/Socket", "<init>");
        net("java/net/ServerSocket", "<init>");
        net("java/net/URL", "openConnection");
        net("java/net/URL", "openStream");
        net("java/net/http/HttpClient", "send");
        net("java/net/http/HttpClient", "sendAsync");
        net("java/nio/channels/SocketChannel", "open");
        net("javax/net/ssl/SSLSocketFactory", "createSocket");

        // ── Exec ───────────────────────────────────────────────────────────────────────────────────
        exec("java/lang/ProcessBuilder", "start");
        exec("java/lang/Runtime", "exec");

        // ── Env ────────────────────────────────────────────────────────────────────────────────────
        env("java/lang/System", "getenv");

        // ── Clock ──────────────────────────────────────────────────────────────────────────────────
        clock("java/lang/System", "currentTimeMillis");
        clock("java/lang/System", "nanoTime");
        clock("java/time/Instant", "now");
        clock("java/time/Clock", "instant");
        clock("java/time/Clock", "millis");
        clock("java/time/Clock", "systemUTC");
        clock("java/time/Clock", "systemDefaultZone");
        clock("java/time/Clock", "system");
        // java/util/Date.<init> no-arg reads the wall clock; the many-arg constructors do not. The
        // transformer can't cheaply gate on descriptor here, so Date.<init> is deliberately OMITTED to
        // stay high-precision (a missed Clock is disclosed-not-witnessed, never a false violation).

        // ── Rand ───────────────────────────────────────────────────────────────────────────────────
        // Only SecureRandom (a real entropy draw). java/util/Random is common + effectively pure PRNG and
        // is deliberately excluded to avoid overclaiming Rand on ordinary code.
        rand("java/security/SecureRandom", "nextBytes");
        rand("java/security/SecureRandom", "nextInt");
        rand("java/security/SecureRandom", "nextLong");
        rand("java/security/SecureRandom", "nextDouble");
        rand("java/security/SecureRandom", "nextFloat");
        rand("java/security/SecureRandom", "nextBoolean");
        rand("java/security/SecureRandom", "nextGaussian");
        rand("java/security/SecureRandom", "next");
        rand("java/security/SecureRandom", "generateSeed");
    }

    /** The effect an {@code (owner, name)} call performs, or {@code null} if it is not an observed boundary. */
    static String effectOf(String owner, String name) {
        if (owner == null || name == null) return null;
        String hit = EXACT.get(owner + "#" + name);
        if (hit != null) return hit;
        // Fallback: any OTHER java/nio/file/Files verb whose name starts with a known read/write/enumerate
        // stem (covers overloads/newer methods not listed above) — still high-precision (Files is an all-Fs
        // façade; its non-effect helpers like getFileStore/probeContentType are rare and harmless if caught).
        if (owner.equals("java/nio/file/Files")) {
            if (name.startsWith("read") || name.startsWith("write") || name.startsWith("newInputStream")
                    || name.startsWith("newOutputStream") || name.startsWith("newBufferedReader")
                    || name.startsWith("newBufferedWriter") || name.startsWith("delete")
                    || name.startsWith("copy") || name.startsWith("move") || name.startsWith("createFile")
                    || name.startsWith("createDirector") || name.equals("lines") || name.equals("list")
                    || name.equals("walk") || name.equals("newByteChannel")) {
                return "Fs";
            }
        }
        return null;
    }
}
