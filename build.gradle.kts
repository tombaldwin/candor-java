plugins {
    application
    id("com.gradleup.shadow") version "9.2.2"
}

// Release version (crate-semver axis), distinct from the `spec` contract version (0.3,
// see candor-spec §2.1) and the git-hash engine build id baked below. Bumped on each
// published artifact; the spec field tracks interface compatibility independently.
version = "0.3.0"
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
    doLast {
        out.get().asFile.apply { parentFile.mkdirs() }
            .writeText("version=$ver\ntoolchain=$tc\n")
    }
}
sourceSets["main"].resources.srcDir(buildInfoDir)
tasks.named("processResources") { dependsOn(generateBuildInfo) }
