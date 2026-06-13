plugins {
    application
    `maven-publish`
    signing
    id("com.gradleup.shadow") version "9.2.2"
}

// Release version (crate-semver axis), distinct from the `spec` contract version (0.3,
// see candor-spec §2.1) and the git-hash engine build id baked below. Bumped on each
// published artifact; the spec field tracks interface compatibility independently.
version = "0.4.4"
group = "io.poly.candor"

repositories { mavenCentral() }
dependencies {
    implementation("org.ow2.asm:asm:9.7")
    implementation("org.ow2.asm:asm-tree:9.7")
    implementation("org.ow2.asm:asm-analysis:9.7") // AS-EFF-007 taint dataflow (Analyzer/Interpreter)
    implementation("com.google.code.gson:gson:2.11.0")
}
java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }
application { mainClass = "candor.Candor" }

// Provenance (candor-spec §2.1): bake the engine build id (git short hash) + toolchain into a resource
// so the report's `candor` header reflects the BINARY that ran, not the source tree it was built from.
fun sh(vararg a: String): String = try {
    ProcessBuilder(*a).redirectErrorStream(true).start()
        .inputStream.bufferedReader().readText().trim()
} catch (e: Exception) { "" }

val candorVersion: String = sh("git", "rev-parse", "--short", "HEAD").ifEmpty { "unknown" }
val candorToolchain: String =
    "jdk-" + (java.toolchain.languageVersion.orNull?.asInt() ?: Runtime.version().feature())

val buildInfoDir = layout.buildDirectory.dir("generated/candor-buildinfo")
val generateBuildInfo by tasks.registering {
    val out = buildInfoDir.map { it.file("candor/build-info.properties") }
    outputs.file(out)
    val ver = candorVersion
    val tc = candorToolchain
    // Declare ver/tc as INPUTS so Gradle re-runs when HEAD (or the JDK) moves. Without this the task
    // was always UP-TO-DATE and baked a STALE build id — two behaviourally different jars then carried
    // the same `version`, defeating the §2.1 version-trust comparison (a /code-review max find: the
    // v0.4.1 release jar predated a guard commit yet reported the same build hash as the rebuild).
    inputs.property("version", ver)
    inputs.property("toolchain", tc)
    doLast {
        out.get().asFile.apply { parentFile.mkdirs() }
            .writeText("version=$ver\ntoolchain=$tc\n")
    }
}
sourceSets["main"].resources.srcDir(buildInfoDir)
tasks.named("processResources") { dependsOn(generateBuildInfo) }

// ---- Publishing (Maven Central via the Central Portal; see PUBLISHING.md for the one-time setup) ----
// Central REQUIRES sources + javadoc jars, a full POM (name/description/url/licenses/scm/developers),
// and GPG signatures. Signing is CONDITIONAL on the key being configured so everyday local builds and
// CI never need it (`./gradlew publishToMavenLocal` works unsigned).
java {
    withSourcesJar()
    withJavadocJar()
}
tasks.named<Javadoc>("javadoc") {
    (options as StandardJavadocDocletOptions).addBooleanOption("Xdoclint:none", true)
}
// sourcesJar packs main resources, which include the generated build-info dir.
tasks.named("sourcesJar") { dependsOn(generateBuildInfo) }

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            // (The shadow plugin already attaches the `-all` fat jar — the `java -jar` / jbang
            // artifact — to the java component; adding it again would duplicate the classifier.)
            pom {
                name = "candor-java"
                description =
                    "Per-method side-effect audit (Fs/Net/Db/Exec/…) for JVM bytecode — the JVM implementation of candor-spec."
                url = "https://candor.poly.io"
                licenses {
                    license { name = "MIT OR Apache-2.0"; url = "https://github.com/tombaldwin/candor-java#license" }
                }
                developers {
                    developer { id = "tombaldwin"; name = "Tom Baldwin"; email = "tom@polymorphism.co.uk" }
                }
                scm {
                    url = "https://github.com/tombaldwin/candor-java"
                    connection = "scm:git:https://github.com/tombaldwin/candor-java.git"
                    developerConnection = "scm:git:git@github.com:tombaldwin/candor-java.git"
                }
            }
        }
    }
}

signing {
    // Only sign when a key is configured (release time) — never block local/CI builds.
    val hasKey = providers.gradleProperty("signing.keyId").isPresent ||
        providers.gradleProperty("signingInMemoryKey").isPresent
    isRequired = hasKey
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        useInMemoryPgpKeys(
            providers.gradleProperty("signingInMemoryKey").get(),
            providers.gradleProperty("signingInMemoryKeyPassword").orNull ?: "",
        )
    }
    if (hasKey) sign(publishing.publications["maven"])
}
