package corpus;

import java.io.*;
import java.nio.file.*;

/**
 * Corpus entry (jfr_diff: Fs) — SOUNDNESS R814. JDK members the κ covered-prefix grant used to certify
 * PURE although they read or write a file inside the call. Each is its own method so the JFR event's top
 * project frame names it; before R814 every one of these read absent from `functions[]`.
 *
 *   loadKeystore  : KeyStore.getInstance(File, char[])   -> FileInputStream.read on the keystore
 *   imageViaStream: ImageIO.read(InputStream)            -> a FileCacheImageInputStream temp file (useCache)
 *   writeXml      : Transformer.transform(.., StreamResult(File)) -> the result file is written
 */
public class JdkSinks {

    static void loadKeystore(File f, char[] pw) throws Exception {
        java.security.KeyStore.getInstance(f, pw);
    }

    static void imageViaStream(byte[] png) throws Exception {
        javax.imageio.ImageIO.read(new ByteArrayInputStream(png));
    }

    static void writeXml(File out) throws Exception {
        var doc = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        doc.appendChild(doc.createElement("r814"));
        javax.xml.transform.TransformerFactory.newInstance().newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc), new javax.xml.transform.stream.StreamResult(out));
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createDirectories(Path.of("/tmp/dyn-corpus/jdk-sinks"));
        char[] pw = "changeit".toCharArray();
        var ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, pw);
        // pad the keystore so its read crosses JFR's event threshold reliably
        for (int i = 0; i < 200; i++) ks.setEntry("k" + i, new java.security.KeyStore.SecretKeyEntry(
                new javax.crypto.spec.SecretKeySpec(new byte[32], "AES")), new java.security.KeyStore.PasswordProtection(pw));
        File ksf = dir.resolve("ks.p12").toFile();
        try (var o = new FileOutputStream(ksf)) { ks.store(o, pw); }
        var img = new java.awt.image.BufferedImage(256, 256, java.awt.image.BufferedImage.TYPE_INT_RGB);
        var bo = new ByteArrayOutputStream();
        javax.imageio.ImageIO.write(img, "png", bo);

        loadKeystore(ksf, pw);
        imageViaStream(bo.toByteArray());
        writeXml(dir.resolve("out.xml").toFile());
        System.out.println("jdk-sinks: done");
    }
}
