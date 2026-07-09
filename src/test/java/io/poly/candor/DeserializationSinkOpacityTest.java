package io.poly.candor;

import io.poly.candor.model.Effect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Code-review sweep 2026-06 teeth, at the classify boundary:
 *
 *  - [#2] Common NON-JDK deserialization / dynamic-class-loading RCE sinks read silent-pure — the same
 *    opacity class as the JDK ObjectInputStream/eval sinks already covered. A `deny Unknown`/`deny Net`
 *    gate would otherwise PASS code that loads & runs an attacker's object graph. Each must classify
 *    → Unknown (the realized effect rides a payload a static pass can't see).
 *
 *  - [#3] commons-configuration2's String-arg → Fs rule was whole-method (any descriptor containing a
 *    String), fabricating Fs on pure builder/factory calls whose String is a property name or encoding.
 *    Verb-gate it to the actual loader methods, mirroring java.nio.file.Files.
 *
 * <p>Originally review round 19 (Round19FixesTest).
 */
class DeserializationSinkOpacityTest {

    // ── [#2] non-JDK RCE / deserialization sinks → Unknown ───────────────────────────────────────────

    @Test
    void snakeYamlLoadIsOpaque() {
        assertEquals(Effect.UNKNOWN, Classifier.classify("org.yaml.snakeyaml.Yaml", "load", "(Ljava/lang/String;)Ljava/lang/Object;"));
        assertEquals(Effect.UNKNOWN, Classifier.classify("org.yaml.snakeyaml.Yaml", "loadAs", "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"));
        // the constructor + dump (serialize) side stay pure — only the inbound parse is the gadget sink
        assertNull(Classifier.classify("org.yaml.snakeyaml.Yaml", "dump", "(Ljava/lang/Object;)Ljava/lang/String;"));
    }

    @Test
    void commonsLang3DeserializeIsOpaque() {
        assertEquals(Effect.UNKNOWN, Classifier.classify("org.apache.commons.lang3.SerializationUtils", "deserialize", "([B)Ljava/lang/Object;"));
        // serialize() is the outbound direction — no untrusted graph materializes → pure
        assertNull(Classifier.classify("org.apache.commons.lang3.SerializationUtils", "serialize", "(Ljava/io/Serializable;)[B"));
    }

    @Test
    void xstreamFromXmlIsOpaque() {
        assertEquals(Effect.UNKNOWN, Classifier.classify("com.thoughtworks.xstream.XStream", "fromXML", "(Ljava/lang/String;)Ljava/lang/Object;"));
        assertNull(Classifier.classify("com.thoughtworks.xstream.XStream", "toXML", "(Ljava/lang/Object;)Ljava/lang/String;"));
    }

    @Test
    void kryoReadIsOpaque() {
        assertEquals(Effect.UNKNOWN, Classifier.classify("com.esotericsoftware.kryo.Kryo", "readObject", "(Lcom/esotericsoftware/kryo/io/Input;Ljava/lang/Class;)Ljava/lang/Object;"));
        assertEquals(Effect.UNKNOWN, Classifier.classify("com.esotericsoftware.kryo.Kryo", "readClassAndObject", "(Lcom/esotericsoftware/kryo/io/Input;)Ljava/lang/Object;"));
        // kryo5 package coordinate (the v5 GA repackage) is the same sink
        assertEquals(Effect.UNKNOWN, Classifier.classify("com.esotericsoftware.kryo.kryo5.Kryo", "readClassAndObject", "(Lcom/esotericsoftware/kryo/kryo5/io/Input;)Ljava/lang/Object;"));
        assertNull(Classifier.classify("com.esotericsoftware.kryo.Kryo", "register", "(Ljava/lang/Class;)Lcom/esotericsoftware/kryo/Registration;"));
    }

    @Test
    void hessianReadObjectIsOpaque() {
        assertEquals(Effect.UNKNOWN, Classifier.classify("com.caucho.hessian.io.HessianInput", "readObject", "()Ljava/lang/Object;"));
    }

    @Test
    void classLoaderLoadAndDefineAreOpaque() {
        // loadClass runs a static initializer on first touch; defineClass materializes attacker bytecode
        assertEquals(Effect.UNKNOWN, Classifier.classify("java.lang.ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"));
        assertEquals(Effect.UNKNOWN, Classifier.classify("java.lang.ClassLoader", "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;"));
        // URLClassLoader: the ctor takes the search URLs, loadClass resolves off them — both opaque
        assertEquals(Effect.UNKNOWN, Classifier.classify("java.net.URLClassLoader", "<init>", "([Ljava/net/URL;)V"));
        assertEquals(Effect.UNKNOWN, Classifier.classify("java.net.URLClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"));
        // MethodHandles.Lookup.defineClass — the modern hidden-class definer
        assertEquals(Effect.UNKNOWN, Classifier.classify("java.lang.invoke.MethodHandles$Lookup", "defineClass", "([B)Ljava/lang/Class;"));
    }

    // ── [#3] commons-configuration2 loader verb-gating (no Fs fabrication on pure calls) ─────────────

    @Test
    void commonsConfig2LoaderVerbsKeepTheirEffect() {
        // the real loaders still read their source: a String/File path → Fs, a URL → Net
        assertEquals(Effect.FS, Classifier.classify("org.apache.commons.configuration2.builder.fluent.Configurations",
                "properties", "(Ljava/lang/String;)Lorg/apache/commons/configuration2/PropertiesConfiguration;"));
        assertEquals(Effect.FS, Classifier.classify("org.apache.commons.configuration2.builder.fluent.Configurations",
                "xml", "(Ljava/io/File;)Lorg/apache/commons/configuration2/XMLConfiguration;"));
        assertEquals(Effect.NET, Classifier.classify("org.apache.commons.configuration2.builder.fluent.Configurations",
                "properties", "(Ljava/net/URL;)Lorg/apache/commons/configuration2/PropertiesConfiguration;"));
    }

    @Test
    void commonsConfig2NonLoaderStringCallsStayPure() {
        // a *Builder() factory takes a path-name String but reads nothing until built — must NOT fabricate Fs
        assertNull(Classifier.classify("org.apache.commons.configuration2.builder.fluent.Configurations",
                "propertiesBuilder", "(Ljava/lang/String;)Lorg/apache/commons/configuration2/builder/FileBasedConfigurationBuilder;"));
        assertNull(Classifier.classify("org.apache.commons.configuration2.builder.fluent.Configurations",
                "xmlBuilder", "(Ljava/lang/String;)Lorg/apache/commons/configuration2/builder/FileBasedConfigurationBuilder;"));
    }
}
