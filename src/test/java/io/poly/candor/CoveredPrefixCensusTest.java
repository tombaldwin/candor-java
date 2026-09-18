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
 * SOUNDNESS R493 — the COVERED-PREFIX CENSUS, {@link CoveredPrefixSubprocessTest} (R486/R487) widened
 * from one effect to the whole list. R492 established the class: a prefix in
 * {@code Rules.KAPPA_COVERED_PREFIXES} suppresses both {@code invisible} and the coverage advisory for
 * its whole namespace, so a member the classifier does not name is not merely unknown — it is
 * <b>silently certified pure</b>. R493 is the same audit carried to the covered prefixes that had no jar
 * in {@code soundness/lib} when R492 ran, and was filed INFERRED for exactly that reason.
 *
 * <p><b>Every assertion below was MEASURED before it was fixed</b>, on a consumer compiled against the
 * real jar (exposed 0.52.0 and ktor 2.3.12 via kotlinc 2.4.10; commons-codec 1.17.0, dbunit 2.8.0,
 * ehcache 3.10.8, redisson 3.31.0, commons-beanutils 1.9.4, super-csv 2.4.0 and aws-sdk auth 2.25.60 via
 * javac), with a JDK control firing on the same tree so an exit 0 could not be a broken scan:
 *
 * <ul>
 *   <li><b>{@code org.jetbrains}</b> held ZERO owner rules while covering {@code org.jetbrains.exposed}.
 *       A ten-method Exposed data layer — connect, transaction, insert, selectAll, update, deleteAll,
 *       SchemaUtils create/drop, raw exec — reported {@code 0 functions reach effects},
 *       {@code coverage: null}, {@code invisible: null}, and {@code deny Db} exited 0. Under ⟨0.21⟩ that
 *       absence from {@code functions} is a certified purity claim, not a hedge.</li>
 *   <li><b>{@code io.ktor}</b> held three owner rules, all CLIENT-side. An HTTP server binding :8080 with
 *       two routes, a {@code respondFile}, a raw TCP connect and a TCP bind read the same way, with
 *       {@code deny Net} exiting 0.</li>
 *   <li><b>{@code org.apache.commons.codec}</b> was granted as "codecs (pure CPU)" and held zero rules —
 *       the {@code org.apache.commons.csv} contradiction of R492, one package over. {@code javap} over
 *       every class in the jar: twelve overloads take a File/Path/RandomAccessFile and open it
 *       themselves.</li>
 *   <li><b>{@code org.dbunit}</b> charged only {@code *Operation.execute} — R480's allowlist shape.</li>
 *   <li><b>{@code org.apache.commons.beanutils}</b> was granted on a survey finding that it "carries NO
 *       effectful members (bean plumbing)"; its two ResultSet-backed DynaClasses walk a live cursor.</li>
 *   <li><b>{@code software.amazon.awssdk.auth.credentials}</b> is the one that is NOT an absence: every
 *       provider read {@code Env}, so {@code ProcessCredentialsProvider} forked a subprocess under a
 *       PASSING {@code deny Exec}. An under-report by EFFECT CLASS is invisible to the "is it in
 *       {@code functions}" test, which is why it is asserted separately below.</li>
 * </ul>
 *
 * <p>The stub owners exist because this build has no kotlinc. What is held constant is the CALL
 * INSTRUCTION — every owner, name and descriptor here was read off the real jar with {@code javap}, and
 * for the two Kotlin libraries off the {@code javap -c} of the real compiled consumer, which is what
 * settles the multifile-facade question the census README names as its known false-positive mode
 * (kotlinc emits {@code QueriesKt}, {@code Database$Companion} and {@code ApplicationResponseFunctionsKt},
 * not the interfaces).
 */
class CoveredPrefixCensusTest {

    private static final Map<String, String> LIB = Map.ofEntries(
        // ── Exposed: the owners `javap -c` shows kotlinc emitting at a real call site ───────────────
        Map.entry("org/jetbrains/exposed/sql/Table.java",
            "package org.jetbrains.exposed.sql;\npublic class Table { public String getTableName() { return null; } }"),
        Map.entry("org/jetbrains/exposed/sql/Query.java",
            "package org.jetbrains.exposed.sql;\npublic class Query { }"),
        Map.entry("org/jetbrains/exposed/sql/Database.java",
            "package org.jetbrains.exposed.sql;\npublic class Database { }"),
        Map.entry("org/jetbrains/exposed/sql/Database$Companion.java", String.join("\n",
            "package org.jetbrains.exposed.sql;",
            "public class Database$Companion {",
            "  public Database connect(String url, String driver) { return null; }",
            "  public Database connect$default(Database$Companion c, String url, String d, int n, Object o) { return null; }",
            "}")),
        Map.entry("org/jetbrains/exposed/sql/Transaction.java", String.join("\n",
            "package org.jetbrains.exposed.sql;",
            "public class Transaction {",
            "  public Object exec(String sql) { return null; }",
            "  public Object exec$default(Transaction t, String sql, int n, Object o) { return null; }",
            "  public String getIdentity() { return null; }",   // a pure accessor — the control
            "}")),
        Map.entry("org/jetbrains/exposed/sql/QueriesKt.java", String.join("\n",
            "package org.jetbrains.exposed.sql;",
            "public final class QueriesKt {",
            "  public static Query selectAll(Table t) { return null; }",
            "  public static Object insert(Table t, Object body) { return null; }",
            "  public static int update$default(Table t, Object w, Integer l, Object b, int n, Object o) { return 0; }",
            "  public static int deleteAll(Table t) { return 0; }",
            "}")),
        Map.entry("org/jetbrains/exposed/sql/SchemaUtils.java", String.join("\n",
            "package org.jetbrains.exposed.sql;",
            "public final class SchemaUtils {",
            "  public static void create$default(SchemaUtils s, Table[] t, boolean w, int n, Object o) {}",
            "  public static void drop$default(SchemaUtils s, Table[] t, boolean w, int n, Object o) {}",
            "  public java.util.List<String> createStatements(Table... t) { return null; }",   // DDL strings only
            "  public java.util.List<Table> sortTablesByReferences(Iterable<Table> t) { return null; }",
            "  public java.util.List<String> listDatabases() { return null; }",
            "}")),
        Map.entry("org/jetbrains/exposed/sql/transactions/ThreadLocalTransactionManagerKt.java", String.join("\n",
            "package org.jetbrains.exposed.sql.transactions;",
            "public final class ThreadLocalTransactionManagerKt {",
            "  public static Object transaction(org.jetbrains.exposed.sql.Database db, Object body) { return null; }",
            "  public static Object inTopLevelTransaction(Object m, Object body) { return null; }",
            "}")),
        Map.entry("org/jetbrains/exposed/sql/transactions/TransactionScopeKt.java", String.join("\n",
            "package org.jetbrains.exposed.sql.transactions;",
            // A DELEGATE FACTORY. It opens nothing, and a `transaction*` PREFIX match charged it — four
            // fabricated <clinit> rows in the corpus A/B. This is why the rule matches exact verbs.
            "public final class TransactionScopeKt {",
            "  public static Object transactionScope(Object init) { return null; }",
            "  public static Object nullableTransactionScope() { return null; }",
            "}")),

        // ── ktor: again, the facade owners a real consumer's bytecode names ─────────────────────────
        Map.entry("io/ktor/server/application/ApplicationCall.java",
            "package io.ktor.server.application;\npublic interface ApplicationCall { Object getRequest(); }"),
        Map.entry("io/ktor/server/engine/EmbeddedServerKt.java", String.join("\n",
            "package io.ktor.server.engine;",
            "public final class EmbeddedServerKt {",
            "  public static Object embeddedServer$default(Object f, int port, Object m, int n, Object o) { return null; }",
            "}")),
        Map.entry("io/ktor/server/netty/NettyApplicationEngine.java", String.join("\n",
            "package io.ktor.server.netty;",
            "public class NettyApplicationEngine {",
            "  public Object start(boolean wait) { return null; }",
            "  public void stop(long a, long b) {}",
            "  public Object getEnvironment() { return null; }",   // pure accessor — the control
            "}")),
        Map.entry("io/ktor/server/response/ApplicationResponseFunctionsKt.java", String.join("\n",
            "package io.ktor.server.response;",
            "public final class ApplicationResponseFunctionsKt {",
            "  public static Object respondText$default(Object call, String t, Object c, Object s, Object h,"
                + " Object k, int n, Object o) { return null; }",
            "}")),
        Map.entry("io/ktor/server/response/ApplicationResponseFunctionsJvmKt.java", String.join("\n",
            "package io.ktor.server.response;",
            "public final class ApplicationResponseFunctionsJvmKt {",
            "  public static Object respondFile$default(Object call, java.io.File f, Object c, int n, Object o) { return null; }",
            "}")),
        Map.entry("io/ktor/server/request/ApplicationReceiveFunctionsKt.java", String.join("\n",
            "package io.ktor.server.request;",
            "public final class ApplicationReceiveFunctionsKt {",
            "  public static Object receiveText(Object call, Object cont) { return null; }",
            "  public static Object receiveNullable(Object call, Object t, Object cont) { return null; }",
            "}")),
        Map.entry("io/ktor/server/routing/RoutingBuilderKt.java", String.join("\n",
            "package io.ktor.server.routing;",
            // Registration only — charging these would put Net on every route table.
            "public final class RoutingBuilderKt {",
            "  public static Object get(Object r, String path, Object body) { return null; }",
            "  public static Object post(Object r, String path, Object body) { return null; }",
            "}")),
        Map.entry("io/ktor/network/sockets/TcpSocketBuilder.java", String.join("\n",
            "package io.ktor.network.sockets;",
            "public class TcpSocketBuilder {",
            "  public Object connect$default(String host, int port, Object c, Object cont, int n, Object o) { return null; }",
            "  public Object bind$default(String host, int port, Object c, int n, Object o) { return null; }",
            "}")),
        Map.entry("io/ktor/network/sockets/BuildersKt.java", String.join("\n",
            "package io.ktor.network.sockets;",
            // aSocket()/tcp() allocate a BUILDER; no descriptor has been opened yet.
            "public final class BuildersKt {",
            "  public static SocketBuilder aSocket(Object selector) { return null; }",
            "}")),
        Map.entry("io/ktor/network/sockets/SocketBuilder.java",
            "package io.ktor.network.sockets;\npublic class SocketBuilder { public TcpSocketBuilder tcp() { return null; } }"),
        Map.entry("io/ktor/utils/io/ByteReadChannelKt.java", String.join("\n",
            "package io.ktor.utils.io;",
            // Pure-relative: the channel's creator carried the effect (the commons-io stance).
            "public final class ByteReadChannelKt {",
            "  public static Object readUTF8Line(Object ch, int limit, Object cont) { return null; }",
            "}")),

        // ── the plain-Java halves, signatures read off the real jars ────────────────────────────────
        Map.entry("org/apache/commons/codec/digest/DigestUtils.java", String.join("\n",
            "package org.apache.commons.codec.digest;",
            "public class DigestUtils {",
            "  public static byte[] digest(java.security.MessageDigest d, java.io.File f) { return null; }",
            "  public static byte[] digest(java.security.MessageDigest d, java.nio.file.Path p,"
                + " java.nio.file.OpenOption... o) { return null; }",
            "  public static String sha256Hex(java.io.InputStream in) { return null; }",   // caller-opened
            "  public static String sha256Hex(byte[] b) { return null; }",                 // pure CPU
            "}")),
        Map.entry("org/apache/commons/codec/digest/HmacUtils.java", String.join("\n",
            "package org.apache.commons.codec.digest;",
            "public class HmacUtils {",
            "  public HmacUtils(String alg, String key) {}",
            "  public byte[] hmac(java.io.File f) { return null; }",
            "  public byte[] hmac(byte[] b) { return null; }",
            "}")),
        Map.entry("org/apache/commons/codec/binary/Base64.java",
            "package org.apache.commons.codec.binary;\npublic class Base64 {"
                + " public static byte[] encodeBase64(byte[] b) { return null; } }"),
        Map.entry("org/dbunit/dataset/IDataSet.java", "package org.dbunit.dataset;\npublic interface IDataSet { }"),
        Map.entry("org/dbunit/dataset/ITable.java",
            "package org.dbunit.dataset;\npublic interface ITable { int getRowCount(); }"),
        Map.entry("org/dbunit/dataset/DefaultTable.java",
            "package org.dbunit.dataset;\npublic class DefaultTable implements ITable { public int getRowCount() { return 0; } }"),
        Map.entry("org/dbunit/database/IDatabaseConnection.java", String.join("\n",
            "package org.dbunit.database;",
            "public interface IDatabaseConnection {",
            "  org.dbunit.dataset.IDataSet createDataSet();",
            "  org.dbunit.dataset.ITable createQueryTable(String name, String sql);",
            "  int getRowCount(String table);",
            "  String getSchema();",
            "}")),
        Map.entry("org/dbunit/database/DatabaseConnection.java", String.join("\n",
            "package org.dbunit.database;",
            "public class DatabaseConnection implements IDatabaseConnection {",
            "  public DatabaseConnection(java.sql.Connection c) {}",
            "  public org.dbunit.dataset.IDataSet createDataSet() { return null; }",
            "  public org.dbunit.dataset.ITable createQueryTable(String n, String s) { return null; }",
            "  public int getRowCount(String t) { return 0; }",
            "  public String getSchema() { return null; }",
            "}")),
        Map.entry("org/dbunit/database/DatabaseDataSourceConnection.java", String.join("\n",
            "package org.dbunit.database;",
            "public class DatabaseDataSourceConnection {",
            "  public DatabaseDataSourceConnection(javax.sql.DataSource ds) {}",
            "  public java.sql.Connection getConnection() { return null; }",
            "}")),
        Map.entry("org/dbunit/util/SQLHelper.java", String.join("\n",
            "package org.dbunit.util;",
            "public class SQLHelper {",
            "  public static boolean tableExists(java.sql.DatabaseMetaData m, String s, String t) { return false; }",
            "  public static boolean schemaExists(java.sql.Connection c, String s) { return false; }",
            "  public static void close(java.sql.ResultSet r) {}",           // no handle param — the control
            "}")),
        Map.entry("org/ehcache/xml/XmlConfiguration.java", String.join("\n",
            "package org.ehcache.xml;",
            "public class XmlConfiguration {",
            "  public XmlConfiguration(java.net.URL u) {}",
            "  public XmlConfiguration(java.io.File f) {}",
            "  public java.util.Map<String, Object> getCacheConfigurations() { return null; }",
            "}")),
        Map.entry("org/apache/commons/beanutils/RowSetDynaClass.java",
            "package org.apache.commons.beanutils;\npublic class RowSetDynaClass {"
                + " public RowSetDynaClass(java.sql.ResultSet rs) {} public String getName() { return null; } }"),
        Map.entry("org/apache/commons/beanutils/ResultSetDynaClass.java",
            "package org.apache.commons.beanutils;\npublic class ResultSetDynaClass {"
                + " public ResultSetDynaClass(java.sql.ResultSet rs) {} public java.util.Iterator<?> iterator() { return null; } }"),
        Map.entry("org/apache/commons/beanutils/BeanUtils.java",
            "package org.apache.commons.beanutils;\npublic class BeanUtils {"
                + " public static void copyProperties(Object a, Object b) {} }"),
        Map.entry("org/apache/commons/validator/ValidatorResources.java", String.join("\n",
            "package org.apache.commons.validator;",
            "public class ValidatorResources {",
            "  public ValidatorResources() {}",                          // an empty ruleset — opens nothing
            "  public ValidatorResources(java.net.URL u) {}",
            "  public ValidatorResources(java.io.InputStream in) {}",    // caller-opened source
            "  public Object getForm(java.util.Locale l, String n) { return null; }",
            "}")),
        Map.entry("org/supercsv/io/CsvResultSetWriter.java",
            "package org.supercsv.io;\npublic class CsvResultSetWriter {"
                + " public CsvResultSetWriter(java.io.Writer w) {} public void write(java.sql.ResultSet rs) {} }"),
        Map.entry("software/amazon/awssdk/auth/credentials/ProcessCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\npublic class ProcessCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/InstanceProfileCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\npublic class InstanceProfileCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/ProfileCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\npublic class ProfileCredentialsProvider"
                + " implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        // ── R496: the DELEGATING resolvers, the interface they are all reached through, and the leaf
        //    providers that must not move. Shapes read off auth-2.25.60 with `javap -p`: the interface
        //    declares `resolveCredentials` and carries a DEFAULT `resolveIdentity(ResolveIdentityRequest)`
        //    whose whole body is `invokeinterface resolveCredentials()`.
        Map.entry("software/amazon/awssdk/identity/spi/ResolveIdentityRequest.java",
            "package software.amazon.awssdk.identity.spi;\npublic interface ResolveIdentityRequest { }"),
        Map.entry("software/amazon/awssdk/auth/credentials/AwsCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\npublic interface AwsCredentialsProvider {"
                + " Object resolveCredentials();"
                + " default java.util.concurrent.CompletableFuture<Object> resolveIdentity("
                + "software.amazon.awssdk.identity.spi.ResolveIdentityRequest r) {"
                + " return java.util.concurrent.CompletableFuture.completedFuture(resolveCredentials()); } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/DefaultCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\npublic class DefaultCredentialsProvider"
                + " implements AwsCredentialsProvider {"
                + " public static DefaultCredentialsProvider create() { return null; }"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/AwsCredentialsProviderChain.java",
            "package software.amazon.awssdk.auth.credentials;\npublic class AwsCredentialsProviderChain"
                + " implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/internal/LazyAwsCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials.internal;\npublic class LazyAwsCredentialsProvider"
                + " implements software.amazon.awssdk.auth.credentials.AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/WebIdentityTokenFileCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\n"
                + "public class WebIdentityTokenFileCredentialsProvider implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/EnvironmentVariableCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\n"
                + "public class EnvironmentVariableCredentialsProvider implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/SystemPropertyCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\n"
                + "public class SystemPropertyCredentialsProvider implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/StaticCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\n"
                + "public class StaticCredentialsProvider implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"),
        Map.entry("software/amazon/awssdk/auth/credentials/AnonymousCredentialsProvider.java",
            "package software.amazon.awssdk.auth.credentials;\n"
                + "public class AnonymousCredentialsProvider implements AwsCredentialsProvider {"
                + " public Object resolveCredentials() { return null; } }"));

    // ── R493: Exposed, end to end ───────────────────────────────────────────────────────────────────

    /** The ten-method Exposed data layer that reported {@code 0 functions reach effects} pre-fix, with
     *  no {@code invisible} and no advisory because {@code org.jetbrains} is κ-covered. */
    @Test
    void exposedDataLayerIsDb() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Dao.java", String.join("\n",
            "package com.x;",
            "import org.jetbrains.exposed.sql.*;",
            "import org.jetbrains.exposed.sql.transactions.ThreadLocalTransactionManagerKt;",
            "public class Dao {",
            "  public Database connect(Database$Companion c) { return c.connect(\"jdbc:h2:mem:t\", \"org.h2.Driver\"); }",
            "  public Object tx(Database db, Object body) { return ThreadLocalTransactionManagerKt.transaction(db, body); }",
            "  public Query all(Table t) { return QueriesKt.selectAll(t); }",
            "  public Object ins(Table t, Object b) { return QueriesKt.insert(t, b); }",
            "  public int del(Table t) { return QueriesKt.deleteAll(t); }",
            "  public void ddl(SchemaUtils s, Table[] t) { SchemaUtils.create$default(s, t, false, 0, null); }",
            "  public Object raw(Transaction t) { return t.exec(\"select 1\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"connect", "tx", "all", "ins", "del", "ddl", "raw"})
                assertTrue(eff(r, "com.x.Dao." + m).contains(Effect.DB),
                    m + " drives the Exposed SQL DSL — must be Db, got " + r.get("com.x.Dao." + m));
        } finally { rm(app.getParent()); }
    }

    // ── R493: ktor's server half, end to end ────────────────────────────────────────────────────────

    /** The HTTP server, the response/request boundary and raw sockets, all reached through the facade
     *  owners kotlinc actually emits. Pre-fix every one was absent with {@code deny Net} exiting 0. */
    @Test
    void ktorServerAndSocketsAreNet() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Web.java", String.join("\n",
            "package com.x;",
            "public class Web {",
            "  public Object serve(Object f, Object mod) {",
            "    return io.ktor.server.engine.EmbeddedServerKt.embeddedServer$default(f, 8080, mod, 0, null); }",
            "  public Object start(io.ktor.server.netty.NettyApplicationEngine e) { return e.start(true); }",
            "  public Object say(Object call) {",
            "    return io.ktor.server.response.ApplicationResponseFunctionsKt"
                + ".respondText$default(call, \"hi\", null, null, null, null, 0, null); }",
            "  public Object sendFile(Object call, java.io.File f) {",
            "    return io.ktor.server.response.ApplicationResponseFunctionsJvmKt"
                + ".respondFile$default(call, f, null, 0, null); }",
            "  public Object read(Object call, Object cont) {",
            "    return io.ktor.server.request.ApplicationReceiveFunctionsKt.receiveText(call, cont); }",
            "  public Object dial(io.ktor.network.sockets.TcpSocketBuilder b, Object cont) {",
            "    return b.connect$default(\"example.com\", 80, null, cont, 0, null); }",
            "  public Object listen(io.ktor.network.sockets.TcpSocketBuilder b) {",
            "    return b.bind$default(\"0.0.0.0\", 9000, null, 0, null); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"serve", "start", "say", "sendFile", "read", "dial", "listen"})
                assertTrue(eff(r, "com.x.Web." + m).contains(Effect.NET),
                    m + " crosses ktor's network boundary — must be Net, got " + r.get("com.x.Web." + m));
        } finally { rm(app.getParent()); }
    }

    // ── R493: the plain-Java halves, end to end ─────────────────────────────────────────────────────

    /** codec / dbunit / ehcache / beanutils / supercsv — each MEASURED absent from {@code functions}
     *  on a consumer compiled against the real jar, with {@code Files.readAllBytes} firing beside it. */
    @Test
    void coveredJavaLibrariesReachTheirEffects() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Lib.java", String.join("\n",
            "package com.x;",
            "public class Lib {",
            "  public byte[] hashFile(java.security.MessageDigest d, java.io.File f) {",
            "    return org.apache.commons.codec.digest.DigestUtils.digest(d, f); }",
            "  public byte[] hashPath(java.security.MessageDigest d, java.nio.file.Path p) {",
            "    return org.apache.commons.codec.digest.DigestUtils.digest(d, p); }",
            "  public byte[] hmacFile(java.io.File f) {",
            "    return new org.apache.commons.codec.digest.HmacUtils(\"HmacSHA256\", \"k\").hmac(f); }",
            "  public Object dataSet(java.sql.Connection c) {",
            "    return new org.dbunit.database.DatabaseConnection(c).createDataSet(); }",
            "  public java.sql.Connection open(javax.sql.DataSource ds) {",
            "    return new org.dbunit.database.DatabaseDataSourceConnection(ds).getConnection(); }",
            "  public boolean exists(java.sql.DatabaseMetaData m) {",
            "    return org.dbunit.util.SQLHelper.tableExists(m, null, \"users\"); }",
            "  public int rows(org.dbunit.database.IDatabaseConnection c) { return c.getRowCount(\"users\"); }",
            "  public Object ehcacheUrl(java.net.URL u) { return new org.ehcache.xml.XmlConfiguration(u); }",
            "  public Object rowSet(java.sql.ResultSet rs) { return new org.apache.commons.beanutils.RowSetDynaClass(rs); }",
            "  public Object cursor(java.sql.ResultSet rs) {",
            "    return new org.apache.commons.beanutils.ResultSetDynaClass(rs).iterator(); }",
            "  public void csv(java.io.Writer w, java.sql.ResultSet rs) {",
            "    new org.supercsv.io.CsvResultSetWriter(w).write(rs); }",
            "  public Object rules(java.net.URL u) { return new org.apache.commons.validator.ValidatorResources(u); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"hashFile", "hashPath", "hmacFile"})
                assertTrue(eff(r, "com.x.Lib." + m).contains(Effect.FS),
                    m + " opens the file itself — must be Fs, got " + r.get("com.x.Lib." + m));
            for (String m : new String[] {"dataSet", "open", "exists", "rows", "rowSet", "cursor", "csv"})
                assertTrue(eff(r, "com.x.Lib." + m).contains(Effect.DB),
                    m + " round-trips to the database — must be Db, got " + r.get("com.x.Lib." + m));
            assertTrue(eff(r, "com.x.Lib.ehcacheUrl").contains(Effect.NET),
                "XmlConfiguration(URL) fetches the config — must be Net, got " + r.get("com.x.Lib.ehcacheUrl"));
            assertTrue(eff(r, "com.x.Lib.rules").contains(Effect.NET),
                "ValidatorResources(URL) fetches the ruleset — must be Net, got " + r.get("com.x.Lib.rules"));
        } finally { rm(app.getParent()); }
    }

    // ── R493: the under-report that is a WRONG CLASS rather than an absence ─────────────────────────

    /** {@code ProcessCredentialsProvider.resolveCredentials} read {@code Env} while {@code javap -c}
     *  shows its private {@code executeCommand()} constructing a {@code java/lang/ProcessBuilder} — so a
     *  {@code deny Exec} gate passed over a real fork. The IMDS provider issues an HTTP GET. Neither is
     *  visible to an "is it in {@code functions}" test, which is the point of asserting all three arms:
     *  the third must STAY {@code Env}, or this fix has simply moved the error. */
    @Test
    void awsCredentialProvidersCarryTheirRealEffect() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Creds.java", String.join("\n",
            "package com.x;",
            "import software.amazon.awssdk.auth.credentials.*;",
            "public class Creds {",
            "  public Object fork(ProcessCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object imds(InstanceProfileCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object profile(ProfileCredentialsProvider p) { return p.resolveCredentials(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            assertTrue(eff(r, "com.x.Creds.fork").contains(Effect.EXEC),
                "ProcessCredentialsProvider forks the credential command — got " + r.get("com.x.Creds.fork"));
            assertTrue(eff(r, "com.x.Creds.imds").contains(Effect.NET),
                "InstanceProfileCredentialsProvider calls the metadata endpoint — got " + r.get("com.x.Creds.imds"));
            assertTrue(eff(r, "com.x.Creds.profile").contains(Effect.ENV),
                "the profile chain still reads the environment — got " + r.get("com.x.Creds.profile"));
        } finally { rm(app.getParent()); }
    }

    // ── R496: the DELEGATING resolvers, found by `weaker_claim_census.py` on its first real run ─────

    /** {@code DefaultCredentialsProvider.create().resolveCredentials()} — the most common AWS credentials
     *  call there is — answered {@code Env} while candor's own scan of auth-2.25.60 gives its body
     *  {@code inferred: [Clock, Env, Exec, Unknown]}. MEASURED on a consumer compiled against the real
     *  jars before the fix: {@code inferred: ['Env']} with {@code invisible: null} and
     *  {@code unresolved: false} — nothing to notice — and {@code deny Exec}, {@code deny Fs},
     *  {@code deny Net} and {@code deny Exec Unknown} ALL exited 0, with a {@code ProcessBuilder} control
     *  on the same tree exiting 1.
     *
     *  <p>Three spellings, because a fix that named only the concrete class would be evaded by the two
     *  that {@code javap -c} shows real consumer bytecode emitting: the INTERFACE
     *  ({@code AwsCredentialsProvider p = DefaultCredentialsProvider.create()}) and
     *  {@code resolveIdentity}, the default method whose body is one {@code invokeinterface
     *  resolveCredentials}. The {@code resolveIdentity} spelling was WORSE than {@code Env}: κ named no
     *  rule for it, the package is κ-covered, and the consumer reported {@code 0 functions reach effects}
     *  with {@code coverage: null} — a ⟨0.21⟩ purity claim over the whole credential chain. */
    @Test
    void awsDelegatingResolversDiscloseTheWholeChain() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Chain.java", String.join("\n",
            "package com.x;",
            "import software.amazon.awssdk.auth.credentials.*;",
            "import software.amazon.awssdk.auth.credentials.internal.LazyAwsCredentialsProvider;",
            "import software.amazon.awssdk.identity.spi.ResolveIdentityRequest;",
            "public class Chain {",
            "  public Object dflt() { return DefaultCredentialsProvider.create().resolveCredentials(); }",
            "  public Object iface() {",
            "    AwsCredentialsProvider p = DefaultCredentialsProvider.create();",
            "    return p.resolveCredentials(); }",
            "  public Object identity(ResolveIdentityRequest q) {",
            "    AwsCredentialsProvider p = DefaultCredentialsProvider.create();",
            "    return p.resolveIdentity(q); }",
            "  public Object profile(ProfileCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object chain(AwsCredentialsProviderChain p) { return p.resolveCredentials(); }",
            "  public Object lazy(LazyAwsCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object web(WebIdentityTokenFileCredentialsProvider p) { return p.resolveCredentials(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String fn : new String[] {"dflt", "iface", "identity", "profile", "chain", "lazy"}) {
                EffectSet e = eff(r, "com.x.Chain." + fn);
                assertTrue(e.contains(Effect.EXEC), fn + ": a profile carrying `credential_process` forks"
                    + " — got " + r.get("com.x.Chain." + fn));
                assertTrue(e.contains(Effect.FS), fn + ": the chain reads ~/.aws/credentials — got " + e);
                assertTrue(e.contains(Effect.NET), fn + ": the chain reaches IMDS/STS — got " + e);
                assertTrue(e.contains(Effect.ENV), fn + ": and it still reads the environment — got " + e);
            }
            // THE ONE CANDIDATE THIS FIX REFUSED. The census reported Exec for it too; `javap -c` shows
            // its ctor building ONE delegate through `WebIdentityCredentialsUtils.factory()` and
            // `resolveCredentials` calling only that. The census's Exec was CHA over the
            // `AwsCredentialsProvider.resolveCredentials` interface call — the higher-order smear its own
            // docstring declares. Asserted so a later widening cannot quietly absorb it.
            EffectSet web = eff(r, "com.x.Chain.web");
            assertTrue(web.contains(Effect.FS) && web.contains(Effect.NET) && web.contains(Effect.ENV),
                "the web-identity provider reads the token file and calls STS — got " + web);
            assertFalse(web.contains(Effect.EXEC),
                "WebIdentityTokenFileCredentialsProvider reaches no fork; charging Exec would be a"
                    + " fabrication imported from a CHA smear — got " + web);
        } finally { rm(app.getParent()); }
    }

    /** R494's fix kept {@code Env} on the providers that only read the environment, so it could not have
     *  merely moved the error sideways; R496 widens the same discipline. These four are LEAVES — each
     *  reads exactly one source — and an exact-equality assertion is what makes the widening above
     *  falsifiable: a prefix rule in place of the owner list turns every one of them red. */
    @Test
    void control_awsLeafCredentialProvidersDoNotMove() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Leaf.java", String.join("\n",
            "package com.x;",
            "import software.amazon.awssdk.auth.credentials.*;",
            "public class Leaf {",
            "  public Object env(EnvironmentVariableCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object prop(SystemPropertyCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object stat(StaticCredentialsProvider p) { return p.resolveCredentials(); }",
            "  public Object anon(AnonymousCredentialsProvider p) { return p.resolveCredentials(); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String fn : new String[] {"env", "prop", "stat", "anon"})
                assertEquals(EffectSet.of(Effect.ENV), eff(r, "com.x.Leaf." + fn),
                    fn + " reads one source; the R496 co-emit must not reach it — got "
                        + r.get("com.x.Leaf." + fn));
        } finally { rm(app.getParent()); }
    }

    // ── OVER-CHARGE CONTROLS ────────────────────────────────────────────────────────────────────────

    /** Executed end-to-end rather than asserted at the table, because an absence-shaped control is
     *  evidence only if the program reaches the branch. Every one of these was an over-charge the first
     *  cut of this fix actually introduced and the 371-jar corpus A/B caught in its ADDED column. */
    @Test
    void control_theCarveOutsStayPure() throws Exception {
        Path app = compileApp(LIB, Map.of("com/x/Pure.java", String.join("\n",
            "package com.x;",
            "public class Pure {",
            // Exposed: a delegate factory, a DDL string builder, a pure accessor.
            "  public Object scope(Object init) {",
            "    return org.jetbrains.exposed.sql.transactions.TransactionScopeKt.transactionScope(init); }",
            "  public Object ddlText(org.jetbrains.exposed.sql.SchemaUtils s,"
                + " org.jetbrains.exposed.sql.Table t) { return s.createStatements(t); }",
            "  public String txId(org.jetbrains.exposed.sql.Transaction t) { return t.getIdentity(); }",
            // ktor: route registration, an engine accessor, a caller-opened channel.
            "  public Object route(Object r, Object body) {",
            "    return io.ktor.server.routing.RoutingBuilderKt.get(r, \"/\", body); }",
            "  public Object env(io.ktor.server.netty.NettyApplicationEngine e) { return e.getEnvironment(); }",
            "  public Object chan(Object ch, Object cont) {",
            "    return io.ktor.utils.io.ByteReadChannelKt.readUTF8Line(ch, 1, cont); }",
            "  public Object sockBuilder(Object sel) {",
            "    return io.ktor.network.sockets.BuildersKt.aSocket(sel).tcp(); }",
            // codec: pure CPU, and the caller-opened stream (STREAM_CONSUMING_UTILITIES stance).
            "  public byte[] b64(byte[] b) { return org.apache.commons.codec.binary.Base64.encodeBase64(b); }",
            "  public String shaBytes(byte[] b) { return org.apache.commons.codec.digest.DigestUtils.sha256Hex(b); }",
            "  public String shaStream(java.io.InputStream in) {",
            "    return org.apache.commons.codec.digest.DigestUtils.sha256Hex(in); }",
            // dbunit: `getRowCount` is two methods with one name, and only one of them queries.
            "  public int memRows(org.dbunit.dataset.ITable t) { return t.getRowCount(); }",
            "  public String schema(org.dbunit.database.IDatabaseConnection c) { return c.getSchema(); }",
            "  public void shut(java.sql.ResultSet rs) { org.dbunit.util.SQLHelper.close(rs); }",
            // ehcache / beanutils: the read-backs.
            "  public Object cfgMap(org.ehcache.xml.XmlConfiguration x) { return x.getCacheConfigurations(); }",
            "  public String dynaName(org.apache.commons.beanutils.RowSetDynaClass d) { return d.getName(); }",
            "  public void copy(Object a, Object b) { org.apache.commons.beanutils.BeanUtils.copyProperties(a, b); }",
            // validator: the empty ruleset opens nothing, the stream form is caller-opened, and the
            // predicate surface batch 29 surveyed really is pure.
            "  public Object emptyRules() { return new org.apache.commons.validator.ValidatorResources(); }",
            "  public Object streamRules(java.io.InputStream in) throws Exception {",
            "    return new org.apache.commons.validator.ValidatorResources(in); }",
            "  public Object form(org.apache.commons.validator.ValidatorResources v, java.util.Locale l) {",
            "    return v.getForm(l, \"f\"); }",
            "}")));
        try {
            Map<String, EffectSet> r = Candor.runScan(app);
            for (String m : new String[] {"scope", "ddlText", "txId", "route", "env", "chan", "sockBuilder",
                    "b64", "shaBytes", "shaStream", "memRows", "schema", "shut", "cfgMap", "dynaName", "copy",
                    "emptyRules", "streamRules", "form"})
                assertTrue(eff(r, "com.x.Pure." + m).isEmpty(),
                    m + " opens nothing and round-trips nowhere — must stay pure, got " + r.get("com.x.Pure." + m));
        } finally { rm(app.getParent()); }
    }

    /** The table-level carve-outs, including the two whose spelling is the whole point: a Kotlin
     *  `object`'s {@code <clinit>}/{@code <init>} allocate the singleton and nothing else, and charging
     *  them put Db on every class that merely TOUCHED the Exposed DAO — four fabricated rows in the
     *  corpus A/B, caught in the ADDED column rather than by any fixture. */
    @Test
    void control_constructionAndDelegatesAreNotEffects() {
        assertNull(Classifier.classify("org.jetbrains.exposed.sql.SchemaUtils", "<clinit>", "()V"));
        assertNull(Classifier.classify("org.jetbrains.exposed.sql.SchemaUtils", "<init>", "()V"));
        assertNull(Classifier.classify("org.jetbrains.exposed.sql.QueriesKt", "<clinit>", "()V"));
        assertNull(Classifier.classify("org.jetbrains.exposed.sql.transactions.TransactionScopeKt",
            "transactionScope", "(Lkotlin/jvm/functions/Function1;)Lkotlin/properties/ReadWriteProperty;"));
        assertNull(Classifier.classify("org.jetbrains.exposed.sql.transactions.TransactionScopeKt",
            "nullableTransactionScope", "()Lkotlin/properties/ReadWriteProperty;"));
        assertNull(Classifier.classify("org.redisson.spring.cache.RedissonCache", "<init>",
            "(Lorg/redisson/api/RMapCache;Lorg/redisson/spring/cache/CacheConfig;Z)V"));
        // …and the ones that must still fire, so the assertions above cannot pass vacuously.
        assertEquals(Effect.DB, Classifier.classify("org.jetbrains.exposed.sql.SchemaUtils",
            "listDatabases", "()Ljava/util/List;"));
        assertEquals(Effect.DB, Classifier.classify("org.jetbrains.exposed.sql.transactions.ThreadLocalTransactionManagerKt",
            "transaction$default", "(Lorg/jetbrains/exposed/sql/Database;Lkotlin/jvm/functions/Function1;ILjava/lang/Object;)Ljava/lang/Object;"));
        assertEquals(Effect.DB, Classifier.classify("org.redisson.spring.cache.RedissonCache",
            "get", "(Ljava/lang/Object;)Lorg/springframework/cache/Cache$ValueWrapper;"));
        assertEquals(Effect.DB, Classifier.classify("org.redisson.jcache.JCache", "put",
            "(Ljava/lang/Object;Ljava/lang/Object;)V"));
        assertEquals(Effect.FS, Classifier.classify("org.redisson.config.Config", "fromYAML",
            "(Ljava/io/File;)Lorg/redisson/config/Config;"));
        assertEquals(Effect.DB, Classifier.classify("org.redisson.Redisson", "create",
            "(Lorg/redisson/config/Config;)Lorg/redisson/api/RedissonClient;"));
    }

    /** {@code getRowCount} at the table, both spellings, because the end-to-end control above can only
     *  show the in-memory one is pure — not that the querying one is still charged after the scoping. */
    @Test
    void control_dbunitGetRowCountIsScopedByOwnerNotByVerb() {
        assertEquals(Effect.DB, Classifier.classify("org.dbunit.database.IDatabaseConnection",
            "getRowCount", "(Ljava/lang/String;)I"));
        assertEquals(Effect.DB, Classifier.classify("org.dbunit.database.AbstractDatabaseConnection",
            "getRowCount", "(Ljava/lang/String;Ljava/lang/String;)I"));
        assertEquals(Effect.DB, Classifier.classify("org.dbunit.database.ScrollableResultSetTable",
            "getRowCount", "()I"));
        for (String t : new String[] {"org.dbunit.dataset.DefaultTable", "org.dbunit.dataset.SortedTable",
                "org.dbunit.dataset.CompositeTable", "org.dbunit.dataset.ReplacementTable",
                "org.dbunit.dataset.excel.XlsTable", "org.dbunit.database.PrimaryKeyFilteredTableWrapper"})
            assertNull(Classifier.classify(t, "getRowCount", "()I"),
                t + ".getRowCount() returns a list size — charging it fabricated Db");
        // `<init>` that WRAPS a caller-opened connection stays pure-relative; the DataSource ctor OPENS.
        assertNull(Classifier.classify("org.dbunit.database.DatabaseConnection", "<init>",
            "(Ljava/sql/Connection;Ljava/lang/String;)V"));
        assertEquals(Effect.DB, Classifier.classify("org.dbunit.database.DatabaseDataSourceConnection",
            "<init>", "(Ljavax/sql/DataSource;)V"));
        assertFalse(Effect.DB.equals(Classifier.classify("org.dbunit.dataset.datatype.AbstractDataType",
            "loadClass", "(Ljava/lang/String;Ljava/sql/Connection;)Ljava/lang/Class;")),
            "loadClass is a Class.forName; the Connection argument is unused");
    }

    // ── harness ─────────────────────────────────────────────────────────────────────────────────────

    private static EffectSet eff(Map<String, EffectSet> r, String fn) {
        return r.getOrDefault(fn, EffectSet.empty());
    }
}
