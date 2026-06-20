import net.ltgt.gradle.errorprone.errorprone

plugins {
    application
    `maven-publish`
    signing
    id("com.gradleup.shadow") version "9.2.2"
    // Error Prone: compile-time bug-pattern detection (==-on-boxed, format-string mismatch, ignored
    // returns, …), many findings carrying a suggested fix. OFF by default — the everyday build and all
    // gates are unchanged. Enable an ADVISORY run with `-Perrorprone`: findings print as warnings and
    // -Werror is dropped for that invocation so they never block (the "advisory before -Werror" posture
    // we used for -Xlint). Promote checks to errors once the codebase is clean. See docs/errorprone.md.
    id("net.ltgt.errorprone") version "5.1.0"
    // OpenRewrite: type-attributed, semantic source refactoring for mechanical/large-scale changes
    // (the safe alternative to regex for ambiguous or signature-changing edits). Recipes are declared in
    // rewrite.yml + listed under `rewrite { activeRecipe(...) }` below. Run `./gradlew rewriteDryRun` to
    // preview a refactor (changes nothing), `rewriteRun` to apply it — then ALWAYS re-run the full gate
    // battery (byte-identity oracle + soundness + conformance). See docs/openrewrite.md.
    id("org.openrewrite.rewrite") version "7.4.1"
}

// Release version (crate-semver axis), distinct from the `spec` contract version (0.3,
// see candor-spec §2.1) and the git-hash engine build id baked below. Bumped on each
// published artifact; the spec field tracks interface compatibility independently.
version = "0.7.8"
group = "io.poly.candor"

repositories { mavenCentral() }

// OpenRewrite recipes to run with `rewriteRun`/`rewriteDryRun`. No recipe is active by default, so
// `rewriteRun` is a safe no-op until you opt one in for a specific refactor (otherwise a stray run could
// churn the whole tree). Add the recipe(s) for the change at hand here, ALWAYS `rewriteDryRun` and review
// the patch first, then `rewriteRun` + the full gate battery. See docs/openrewrite.md.
//   NOTE: org.openrewrite.java.RemoveUnusedImports is the canonical demonstrator but on this codebase it
//   UNFOLDS our wildcard imports (import ...tree.* -> explicit classes) across ~50 files — against our
//   established style — so it is deliberately NOT activated. (Verified via rewriteDryRun.)
rewrite {
    // activeRecipe("io.poly.candor.YourRecipe")   // <- opt in per refactor (define in rewrite.yml)
}

dependencies {
    implementation("org.ow2.asm:asm:9.8")
    implementation("org.ow2.asm:asm-tree:9.8")
    implementation("org.ow2.asm:asm-analysis:9.8") // AS-EFF-007 taint dataflow (Analyzer/Interpreter)
    implementation("com.google.code.gson:gson:2.11.0")
    // OpenRewrite recipe modules available to the recipes above (the BOM pins a coherent set). The core
    // java recipes (RemoveUnusedImports, ChangeType/ChangeMethodName, …) ship with the plugin; this BOM
    // + static-analysis adds the best-practices recipe library for future custom/composed recipes.
    rewrite(platform("org.openrewrite.recipe:rewrite-recipe-bom:3.33.0"))
    rewrite("org.openrewrite.recipe:rewrite-static-analysis")
    // Error Prone analyzer (used only when -Perrorprone is set; the plugin auto-adds the jdk.compiler
    // --add-exports and forks javac on JDK 16+).
    errorprone("com.google.errorprone:error_prone_core:2.50.0")
    // Native unit tests (JUnit 5). junit-platform-launcher must be declared explicitly on Gradle 9+.
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.2")
}
java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }
application { mainClass = "io.poly.candor.Candor" }
tasks.named<Test>("test") { useJUnitPlatform() }

// Lint gate: javac's own -Xlint, warnings-as-errors. The engine is single-module hand-written Java;
// -Xlint catches the real footguns (unchecked/rawtypes, fallthrough, finally, overrides) without a
// third-party analyzer's setup cost. `this-escape` and `processing` are filtered: the former fires on
// legitimate constructor patterns, the latter only matters with annotation processors (none here).
// Error Prone is an explicit, advisory opt-in: `-Perrorprone` enables it AND drops -Werror for that run
// so its findings (and any -Xlint warning) print without failing the build. Default builds are byte-for-
// byte the same as before this plugin existed.
val errorproneOn = (providers.gradleProperty("errorprone").orNull ?: "false") != "false"
tasks.withType<JavaCompile>().configureEach {
    val args = mutableListOf("-Xlint:all,-this-escape,-processing")
    if (!errorproneOn) args.add("-Werror")
    options.compilerArgs.addAll(args)
    options.errorprone.enabled.set(errorproneOn)
    if (errorproneOn) {
        options.errorprone.allErrorsAsWarnings.set(true)
        // Triaged + cleaned (the soundness cluster) — promote to ERROR so a regression fails the
        // `-Perrorprone` run. Intentional exceptions carry @SuppressWarnings with a why. Everything else
        // (StringSplitter — all sites guarded; style checks) stays an advisory warning for now.
        options.errorprone.error(
            "StringCaseLocaleUsage", "ReferenceEquality", "EmptyCatch", "NotJavadoc",
        )
    }
}

// Provenance (candor-spec §2.1): bake the engine build id (git short hash) + toolchain into a resource
// so the report's `candor` header reflects the BINARY that ran, not the source tree it was built from.
fun sh(vararg a: String): String = try {
    ProcessBuilder(*a).redirectErrorStream(true).start()
        .inputStream.bufferedReader().readText().trim()
} catch (e: Exception) { "" }

val candorVersion: String = sh("git", "rev-parse", "--short", "HEAD").ifEmpty { "unknown" }
val candorToolchain: String =
    "jdk-" + (java.toolchain.languageVersion.orNull?.asInt() ?: Runtime.version().feature())
// The clean release semver (the crate-semver axis, == this Gradle project `version`). Distinct from
// the git-hash build id baked as `version` above: GitHub releases tag and the `-all.jar` filename
// carry THIS, and `--version` reports it. Baked as `release` so the binary reports its release
// identity without re-deriving it from the manifest.
val candorRelease: String = project.version.toString()

val buildInfoDir = layout.buildDirectory.dir("generated/candor-buildinfo")
val generateBuildInfo by tasks.registering {
    val out = buildInfoDir.map { it.file("candor/build-info.properties") }
    outputs.file(out)
    val ver = candorVersion
    val tc = candorToolchain
    val rel = candorRelease
    // Declare ver/tc as INPUTS so Gradle re-runs when HEAD (or the JDK) moves. Without this the task
    // was always UP-TO-DATE and baked a STALE build id — two behaviourally different jars then carried
    // the same `version`, defeating the §2.1 version-trust comparison (a /code-review max find: the
    // v0.4.1 release jar predated a guard commit yet reported the same build hash as the rebuild).
    inputs.property("version", ver)
    inputs.property("toolchain", tc)
    inputs.property("release", rel)
    doLast {
        out.get().asFile.apply { parentFile.mkdirs() }
            .writeText("version=$ver\ntoolchain=$tc\nrelease=$rel\n")
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
