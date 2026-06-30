package io.poly.candor;

import io.poly.candor.model.Effect;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS PROBE for the arbitrary-code-execution / untrusted-deserialization sinks (Classifier §"ARBITRARY-
 * CODE-EXECUTION / OPAQUE sinks"). Each of these reads SILENT-PURE in plain bytecode (no classify row, and
 * their JDK/library packages are even κ-"covered" so undisclosed) — yet each runs an attacker-controlled
 * object graph / bytecode and can perform ANY effect. The contract: they classify as `Unknown`, so a
 * `deny Net`/`deny Unknown` gate can't be tricked into passing on RCE. A regression that quietly drops one
 * back to pure (null) would re-open the exact gate-evasion these rules close — pin them at the method
 * boundary (the same direct-classify idiom as HelpersTest). Mirrors Classifier.java:90-107.
 */
class RceSinkClassifierTest {

    /** Each sink must classify Unknown — never null (pure) and never a concrete effect that would let a
     *  narrow `deny <Effect>` gate miss the rest of the realized-effect surface. */
    private static void assertUnknown(String owner, String method, String desc) {
        assertEquals(Effect.UNKNOWN, Classifier.classify(owner, method, desc),
                owner + "." + method + " is an RCE/deserialization sink — must be Unknown, never silent-pure");
    }

    /** SnakeYAML — RCE-by-default pre-2.0; load/loadAs instantiate arbitrary types from the document. */
    @Test
    void snakeYamlLoadIsUnknown() {
        assertUnknown("org.yaml.snakeyaml.Yaml", "load", "(Ljava/lang/String;)Ljava/lang/Object;");
        assertUnknown("org.yaml.snakeyaml.Yaml", "loadAs", "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;");
    }

    /** commons-lang3 SerializationUtils.deserialize — a thin ObjectInputStream wrapper (gadget-chain RCE). */
    @Test
    void commonsSerializationUtilsDeserializeIsUnknown() {
        assertUnknown("org.apache.commons.lang3.SerializationUtils", "deserialize", "([B)Ljava/lang/Object;");
    }

    /** XStream.fromXML — reconstructs an arbitrary object graph from XML (classic gadget sink). */
    @Test
    void xstreamFromXmlIsUnknown() {
        assertUnknown("com.thoughtworks.xstream.XStream", "fromXML", "(Ljava/lang/String;)Ljava/lang/Object;");
    }

    /** Kryo (both the legacy `kryo` and `kryo5` coordinates) — readObject/readClassAndObject. */
    @Test
    void kryoReadIsUnknown() {
        assertUnknown("com.esotericsoftware.kryo.Kryo", "readObject",
                "(Lcom/esotericsoftware/kryo/io/Input;Ljava/lang/Class;)Ljava/lang/Object;");
        assertUnknown("com.esotericsoftware.kryo.Kryo", "readClassAndObject",
                "(Lcom/esotericsoftware/kryo/io/Input;)Ljava/lang/Object;");
        assertUnknown("com.esotericsoftware.kryo.kryo5.Kryo", "readObject",
                "(Lcom/esotericsoftware/kryo/kryo5/io/Input;Ljava/lang/Class;)Ljava/lang/Object;");
        assertUnknown("com.esotericsoftware.kryo.kryo5.Kryo", "readClassAndObject",
                "(Lcom/esotericsoftware/kryo/kryo5/io/Input;)Ljava/lang/Object;");
    }

    /** Hessian — HessianInput.readObject deserializes an attacker-controlled binary object graph. */
    @Test
    void hessianReadObjectIsUnknown() {
        assertUnknown("com.caucho.hessian.io.HessianInput", "readObject", "()Ljava/lang/Object;");
    }

    /** Dynamic class loading / definition: loadClass can run a static initializer (arbitrary code on first
     *  touch) and defineClass materializes attacker-supplied bytecode — ClassLoader, the URLClassLoader
     *  subclass (ctor takes the search URLs), and the modern MethodHandles.Lookup.defineClass definer. */
    @Test
    void classLoadingAndDefinitionIsUnknown() {
        assertUnknown("java.lang.ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        assertUnknown("java.lang.ClassLoader", "defineClass",
                "(Ljava/lang/String;[BII)Ljava/lang/Class;");
        assertUnknown("java.net.URLClassLoader", "<init>", "([Ljava/net/URL;)V");
        assertUnknown("java.net.URLClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        assertUnknown("java.lang.invoke.MethodHandles$Lookup", "defineClass", "([B)Ljava/lang/Class;");
    }
}
