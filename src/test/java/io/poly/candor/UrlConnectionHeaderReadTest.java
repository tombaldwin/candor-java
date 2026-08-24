package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.poly.candor.model.EffectSet;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * <b>A FOUR-METHOD CLASS THAT DOES NOTHING BUT READ HTTP HEADERS PASSED {@code deny Net} AT EXIT 0 WITH
 * AN EMPTY FUNCTION LIST.</b> The classifier's lazy-connection arm enumerated the verbs that LOOK like
 * transmission — {@code connect}, {@code getInputStream}, {@code getOutputStream}, {@code getContent},
 * {@code getResponseCode}, {@code getResponseMessage} — and stopped there. Reading a header is a round
 * trip too; it just does not look like one at the call site.
 *
 * <p>The JDK says so in its own source. {@code sun/net/www/URLConnection.getHeaderField} opens with
 * {@code try { getInputStream(); }}, and the HTTP protocol handler does the same in every one of its
 * {@code getHeaderField*} overrides. The rest of the family is defined AS a call to it —
 * {@code getContentType()} is {@code getHeaderField("content-type")}, {@code getContentLengthLong()} is
 * {@code getHeaderFieldLong("content-length", -1)}. So `Content-Length` polling, `Last-Modified` cache
 * validation and `ETag` checks — the ordinary reasons to touch a URL without reading its body — were the
 * shapes candor was blindest to.
 *
 * <p>Present in spring-web, jsoup and commons-io in the local JVM corpus.
 *
 * <p>The unit table lives in {@code HelpersTest}; this asks the question end to end, through real
 * bytecode, because a classifier row proves nothing about whether the RECEIVER at a call site reaches it.
 */
class UrlConnectionHeaderReadTest {

    /** Compile the fixture, drive a real {@link Candor#runScan}, clean up. */
    private static Map<String, EffectSet> compileAndScan(Map<String, String> sources) throws Exception {
        Path out = TestCompiler.compile(sources);
        try {
            return Candor.runScan(out);
        } finally {
            TestCompiler.rm(out.getParent());
        }
    }

    private static List<String> fx(Map<String, EffectSet> m, String fn) {
        return m.getOrDefault(fn, EffectSet.empty()).toNames();
    }

    /** THE DEFECT. Four methods, four header reads, nothing else. */
    @Test
    void headerReadsReachNet() throws Exception {
        var m = compileAndScan(Map.of("app/Headers.java",
                "package app;\n"
                + "import java.net.HttpURLConnection;\n"
                + "import java.net.URLConnection;\n"
                + "public class Headers {\n"
                + "  public String type(URLConnection c) { return c.getContentType(); }\n"
                + "  public long size(URLConnection c) { return c.getContentLengthLong(); }\n"
                + "  public String etag(URLConnection c) { return c.getHeaderField(\"ETag\"); }\n"
                + "  public long mod(HttpURLConnection c) { return c.getLastModified(); }\n"
                + "  public java.util.Map<String,java.util.List<String>> all(HttpURLConnection c) { return c.getHeaderFields(); }\n"
                + "}\n"));
        for (String fn : new String[]{"app.Headers.type", "app.Headers.size", "app.Headers.etag",
                                      "app.Headers.mod", "app.Headers.all"})
            assertTrue(fx(m, fn).contains("Net"),
                    fn + " reads an HTTP response header, which opens the connection in the JDK's own "
                    + "impl — it must reach Net. Got " + fx(m, fn));
    }

    /**
     * THE OVER-CHARGE CONTROL, and it is the deliverable as much as the assertion above. A method that
     * only CONFIGURES a request — the surface the JDK source shows returning or assigning a field — must
     * stay pure. The safe-looking widening (whole-owner Net on URLConnection) passes the defect assertion
     * while fabricating Net on every builder-style helper in every HTTP client wrapper in the corpus.
     */
    @Test
    void requestSideConfigurationStaysPure() throws Exception {
        var m = compileAndScan(Map.of("app/Prepare.java",
                "package app;\n"
                + "import java.net.HttpURLConnection;\n"
                + "import java.net.URLConnection;\n"
                + "public class Prepare {\n"
                + "  public void auth(URLConnection c, String tok) { c.setRequestProperty(\"Authorization\", tok); }\n"
                + "  public void tune(URLConnection c) { c.setConnectTimeout(5000); c.setReadTimeout(5000); c.setUseCaches(false); }\n"
                + "  public java.net.URL where(URLConnection c) { return c.getURL(); }\n"
                + "  public String verb(HttpURLConnection c) { return c.getRequestMethod(); }\n"
                + "  public void post(HttpURLConnection c) throws Exception { c.setRequestMethod(\"POST\"); c.setDoOutput(true); }\n"
                + "}\n"));
        for (String fn : new String[]{"app.Prepare.auth", "app.Prepare.tune", "app.Prepare.where",
                                      "app.Prepare.verb", "app.Prepare.post"})
            assertFalse(fx(m, fn).contains("Net"),
                    fn + " only configures the request — no byte leaves the process. A Net here is the "
                    + "cardinal sin's mirror: a fabrication, and it would fire on every HTTP wrapper in "
                    + "the corpus. Got " + fx(m, fn));
    }

    /**
     * THE SECOND CONTROL: a PROJECT type that merely shares the name. The classifier matches the fully
     * qualified owner, and this fixture is what keeps a future `endsWith("URLConnection")` repair — which
     * reads entirely plausible — from fabricating Net across every app that names a class this.
     */
    @Test
    void aProjectClassNamedUrlConnectionIsNotTheJdks() throws Exception {
        var m = compileAndScan(Map.of(
            "app/net/URLConnection.java",
                "package app.net;\n"
                + "public class URLConnection {\n"
                + "  private final java.util.Map<String,String> h = new java.util.HashMap<>();\n"
                + "  public String getContentType() { return h.get(\"content-type\"); }\n"
                + "  public String getHeaderField(String n) { return h.get(n); }\n"
                + "  public java.util.Map<String,String> getHeaderFields() { return h; }\n"
                + "  public long getLastModified() { return 0L; }\n"
                + "}\n",
            "app/Use.java",
                "package app;\n"
                + "public class Use {\n"
                + "  public String go(app.net.URLConnection c) { return c.getContentType(); }\n"
                + "  public String one(app.net.URLConnection c) { return c.getHeaderField(\"ETag\"); }\n"
                + "}\n"));
        for (String fn : new String[]{"app.net.URLConnection.getContentType", "app.net.URLConnection.getHeaderField",
                                      "app.net.URLConnection.getHeaderFields", "app.net.URLConnection.getLastModified",
                                      "app.Use.go", "app.Use.one"})
            assertEquals(List.of(), fx(m, fn),
                    fn + " belongs to a PROJECT class that only shares a simple name with the JDK's. "
                    + "Got " + fx(m, fn));
    }
}
