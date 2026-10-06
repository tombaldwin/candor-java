package io.poly.candor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static io.poly.candor.TestCompiler.compileApp;
import static io.poly.candor.TestCompiler.rm;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R925 — an effect a call site adds BESIDE {@code classify}'s single slot must reach the masking
 * guards. The S3 transfer {@code Fs}, the AWS credential chain's {@code Fs}/{@code Net}/{@code Exec} and jgit's
 * {@code Exec}/{@code Fs} were added straight into the effect set, so a benign sibling literal of the same
 * effect certified them. EXECUTED in the lane's fixture (S3 against a local endpoint: the transfer wrote and
 * read caller-chosen files; the chain read a credentials file named by configuration). Stubs here carry the
 * real owner names; the bodies are irrelevant because the owners are classified by name.
 */
class SideChargeLocatorTest {

    private static boolean inc(String fn, String e) {
        return AnalysisState.ctx().surfaceIncomplete.getOrDefault(fn, new TreeSet<>()).contains(e);
    }

    private static final Map<String, String> LIB = Map.of(
        "software/amazon/awssdk/services/s3/S3Client.java", "package software.amazon.awssdk.services.s3;"
            + " public interface S3Client { Object getObject(Object req, java.nio.file.Path p); Object putObject(Object req, java.nio.file.Path p); }",
        "software/amazon/awssdk/auth/credentials/DefaultCredentialsProvider.java", "package software.amazon.awssdk.auth.credentials;"
            + " public class DefaultCredentialsProvider { public static DefaultCredentialsProvider create() { return null; }"
            + " public Object resolveCredentials() { return null; } }",
        "org/eclipse/jgit/api/Git.java", "package org.eclipse.jgit.api; public class Git { public static Git open(java.io.File f) { return null; } }",
        "org/eclipse/jgit/storage/file/FileRepositoryBuilder.java", "package org.eclipse.jgit.storage.file;"
            + " public class FileRepositoryBuilder { public FileRepositoryBuilder setGitDir(java.io.File f) { return this; } public Object build() { return null; } }");

    private static final String FS = "java.nio.file.Files.write(java.nio.file.Paths.get(\"/tmp/benign/x\"), new byte[0]); ";

    @Test
    void everySideChargeIsJudgedLikeAClassifiedOne() throws Exception {
        Path app = compileApp(LIB, Map.of("app/A.java", String.join("\n",
            "package app;",
            "import java.nio.file.*; import java.io.File;",
            "public class A {",
            "  void s3get(software.amazon.awssdk.services.s3.S3Client c, Path p) throws Exception { " + FS + "c.getObject(null, p); }",
            "  void s3put(software.amazon.awssdk.services.s3.S3Client c, Path p) throws Exception { " + FS + "c.putObject(null, p); }",
            "  void credsFs() throws Exception { " + FS + "software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider.create().resolveCredentials(); }",
            "  void credsNet() throws Exception { new java.net.URL(\"https://good.example/\").openStream();"
                + " software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider.create().resolveCredentials(); }",
            "  void jgitExec(File f) throws Exception { new ProcessBuilder(\"/bin/echo\").start(); org.eclipse.jgit.api.Git.open(f); }",
            "  void jgitBuild(File f) throws Exception { " + FS + "new org.eclipse.jgit.storage.file.FileRepositoryBuilder().setGitDir(f).build(); }",
            // control: a DETERMINED in-dir path on the S3 transfer stays certifiable for Fs
            "  void ctlS3(software.amazon.awssdk.services.s3.S3Client c) throws Exception { " + FS + "c.getObject(null, Paths.get(\"/tmp/benign/dl\")); }",
            "}")));
        try {
            Candor.runScan(app);
            for (String m : new String[] {"s3get", "s3put", "credsFs", "jgitBuild"})
                assertTrue(inc("app.A." + m, "Fs"), m + ": the file this side charge touches is invisible — must mark Fs");
            assertTrue(inc("app.A.credsNet", "Net"), "the credential chain's endpoint is never in source — must mark Net");
            assertTrue(inc("app.A.jgitExec", "Exec"), "jgit forks `git`, never named in source — must mark Exec");
            assertFalse(inc("app.A.ctlS3", "Fs"), "a determined literal transfer path must stay certifiable");
        } finally { rm(app.getParent()); }
    }
}
