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
    // GraalVM native-image: build a standalone `candor` binary with ~native startup (no JVM warmup) —
    // the big win for a CLI run on every push / in agent loops. `./gradlew nativeCompile` (Gradle
    // auto-provisions a GraalVM toolchain via the foojay resolver). See docs/native-image.md.
    id("org.graalvm.buildtools.native") version "1.1.2"
}

// Release version (crate-semver axis), distinct from the `spec` contract version (0.3,
// see candor-spec §2.1) and the git-hash engine build id baked below. Bumped on each
// published artifact; the spec field tracks interface compatibility independently.
version = "0.40.3"
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

// GraalVM native-image. candor reads two bundled RESOURCES via getResourceAsStream (AGENTS.md, the
// build-info.properties provenance) — included below. It does NO reflection on analysed classes (ASM
// reads bytes), and serializes only Maps/Lists via Gson (whose own native-image metadata ships in the
// gson jar). --no-fallback makes a missing config a hard error rather than a silent JVM-fallback image.
//
// IT DOES REFLECT ON ONE OF ITS OWN CLASSES, and this comment used to end "so no candor-specific
// reflection config is needed" — accurate when written, false from ⟨0.32⟩ (acd1e0e), and nothing
// measured it in between. The refresh overlay derives its accumulator set from
// AnalysisContext.getDeclaredFields(); with no metadata a native image answers ZERO FIELDS and does not
// throw, so the per-class delta merge folded nothing and the binary reported 0 effects over a tree the
// jar found 210 in. Registered in
// src/main/resources/META-INF/native-image/io.poly.candor/candor-java/reflect-config.json; the engine
// now refuses to run on an empty field set, and native.yml's parity gate is what catches the next one.
graalvmNative {
    toolchainDetection.set(true)
    // The plugin's bundled GraalVM reachability-metadata repository requires a recent GraalVM. candor
    // needs none of it — its only reflective dependency (Gson) ships its own metadata inside the gson jar
    // — so disable it (keeps the build working on a GraalVM CE 21 toolchain).
    metadataRepository { enabled.set(false) }
    binaries {
        named("main") {
            imageName.set("candor")
            mainClass.set("io.poly.candor.Candor")
            buildArgs.add("--no-fallback")
            buildArgs.add("-H:IncludeResources=AGENTS\\.md")
            buildArgs.add("-H:IncludeResources=candor/build-info\\.properties")
            // The build-time JDK supertype index — candor reads JDK class hierarchies off its runtime
            // classpath via ASM on the JVM, but a native image has no .class files; this index lets
            // Cha.externalSupers resolve JDK hierarchies in native, keeping native == jar (see Cha).
            buildArgs.add("-H:IncludeResources=candor/jdk-supertypes\\.idx\\.gz")
            // SOUNDNESS R191 — the build-time JDK functional-interface SAM index, read by
            // Candor.samNameOf on BOTH artifacts (there is no runtime ClassReader path to fall back
            // to, by design), so leaving it out of the image would make the native binary silent on
            // exactly the method references the jar discloses.
            buildArgs.add("-H:IncludeResources=candor/jdk-sams\\.idx\\.gz")
            // SOUNDNESS R237 — the build-time JDK invoking-higher-order-function index, read by
            // Candor.jdkInvokesFunctionalArg on BOTH artifacts for the same reason as the SAM index:
            // leaving it out would make the native binary SILENT on exactly the callbacks the jar
            // discloses, which is the one-artifact guard §L is about.
            buildArgs.add("-H:IncludeResources=candor/jdk-hof-invokes\\.idx\\.gz")
            // SOUNDNESS R492/R727 — the GENERATED framework member -> effect table (FrameworkReach). Missing from
            // the image, the native binary would read every member it charges as silently pure again.
            buildArgs.add("-H:IncludeResources=candor/framework-reach\\.tsv")
            buildArgs.add("-H:IncludeResources=candor/framework-hedge\\.tsv")
        }
    }
}

// SOUNDNESS R249 — THE LINES ABOVE WERE UNGATED, AND DROPPING ONE IS A SILENT UNDER-REPORT.
//
// Each `-H:IncludeResources` line bundles a classifier index into the native image. A missing index
// does not fail, does not warn and does not disclose: every loader degrades to an empty map, so the
// binary answers exactly what it answered before that index existed — measured, stripping each resource
// from the shipped fat jar: exit 0, ZERO stderr lines, and `Optional.orElseGet(supParam)` /
// `Objects.requireNonNullElseGet` fall from `['Unknown']` back to ABSENT.
//
// `native.yml`'s parity gate is supposed to be what catches that, and it could not: measured over its
// target (`build/classes/java/main`), stripping ANY of the three left 610 functions / 1,397 analyzed and
// a byte-identical envelope. Its non-vacuousness control passed throughout, because that control proves
// the SCAN found something, not that a RESOURCE was consulted. `src/nativeParity` + `ci/native-parity.py`
// are the behavioural half of the answer, and their NATIVE leg needs GraalVM (the verdict itself does not —
// `ci/native-parity-selftest.sh` attacks it here).
//
// THIS TASK IS THE HALF THAT DOES NOT. It compares two lists that both already exist — the resources
// `processResources` really produced, and the `IncludeResources` patterns this file really declares — so
// a deleted or mistyped line fails on any machine, in seconds, with no native-image toolchain. It reads
// the patterns off the extension rather than repeating them, because a second hand-written copy of a
// list is the drift this repo keeps finding (corpus brief §F1-q3).
//
// BOTH DIRECTIONS, and the second is the one that catches a stripped resource rather than a dropped
// line: every runtime resource must be matched by some pattern, AND every pattern must match some
// resource. `META-INF/native-image/**` is excluded because native-image reads that directory as
// CONFIGURATION on its own — it is not an `IncludeResources` bundle and never was.
val nativeImageIncludeResourcePatterns: Provider<List<String>> = provider {
    graalvmNative.binaries.getByName("main").buildArgs.get()
        .filter { it.startsWith("-H:IncludeResources=") }
        .map { it.removePrefix("-H:IncludeResources=") }
}
val verifyNativeImageResources by tasks.registering {
    group = "verification"
    description = "SOUNDNESS R249 — every bundled resource is named by an -H:IncludeResources line, and back."
    dependsOn(tasks.named("processResources"))
    val resDir = layout.buildDirectory.dir("resources/main")
    val patterns = nativeImageIncludeResourcePatterns
    inputs.dir(resDir)
    inputs.property("includeResourcePatterns", patterns)
    outputs.upToDateWhen { false }   // a two-list comparison over a handful of files; never worth skipping
    doLast {
        val root = resDir.get().asFile
        val files = root.walkTopDown().filter { it.isFile }
            .map { it.relativeTo(root).invariantSeparatorsPath }
            .filterNot { it.startsWith("META-INF/native-image/") }
            .toList().sorted()
        val pats = patterns.get()
        check(files.isNotEmpty()) {
            "R249: no runtime resources found under $root — this gate would then be comparing two empty " +
                "lists and passing. Zero resources is not zero findings."
        }
        val compiled = pats.map { it to Regex(it) }
        val unbundled = files.filter { f -> compiled.none { (_, re) -> re.matches(f) } }
        val dead = compiled.filter { (_, re) -> files.none { re.matches(it) } }.map { it.first }
        val problems = buildList {
            if (unbundled.isNotEmpty()) add(
                "these runtime resources are NOT named by any -H:IncludeResources line, so a native image\n" +
                    "  will not carry them and every loader that reads one degrades SILENTLY to an empty map:\n" +
                    unbundled.joinToString("\n") { "    $it" } +
                    "\n  Fix: add `buildArgs.add(\"-H:IncludeResources=<regex>\")` in the graalvmNative block above.",
            )
            if (dead.isNotEmpty()) add(
                "these -H:IncludeResources patterns match NO resource, so they bundle nothing — either the\n" +
                    "  resource stopped being generated or the pattern is mistyped:\n" +
                    dead.joinToString("\n") { "    $it" },
            )
        }
        check(problems.isEmpty()) {
            "SOUNDNESS R249 — native-image resource declaration is out of step with the resources built.\n" +
                problems.joinToString("\n") { "  $it" } +
                "\n  Declared patterns: $pats\n  Built resources:   $files"
        }
        logger.lifecycle(
            "R249: ${files.size} runtime resource(s), each named by one of ${pats.size} " +
                "-H:IncludeResources pattern(s)",
        )
    }
}
// Runs on every build path that produces resources — `test`, `shadowJar` and `nativeCompile` all pull
// `classes`, which pulls `processResources`. It is also an explicit `ci.yml` step so that
// `candor/bin/gates.sh candor-java` PRINTS it: a gate reachable only as a side effect of another task
// is invisible to the per-repo gate list, and a gate nobody knows to run is the shape R249 is about.
tasks.named("processResources") { finalizedBy(verifyNativeImageResources) }

// SOUNDNESS R249 — THE NATIVE-PARITY FIXTURE. A separate source set, deliberately outside `main` (it must
// never reach the shadow jar) and outside `test` (the parity gate scans a CLASSES DIRECTORY, and mixing
// it into the test tree would put JUnit on the scanned target). `build/classes/java/nativeParity` is what
// `native.yml` hands to both legs. Compiled with the same toolchain, the same `--release 17` and the same
// `-Xlint:all -Werror` as everything else here, so it cannot drift into being unbuildable unnoticed.
sourceSets {
    create("nativeParity") { java.srcDir("src/nativeParity/java") }
}

java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }
// Build WITH the JDK 21 toolchain but emit Java 17 bytecode so the tool RUNS on any Java 17+ runtime —
// candor is a bytecode analyzer, not an app; requiring Java 21 to run it needlessly excludes 17-LTS CI
// (the adopt GitHub Action hit exactly this: UnsupportedClassVersionError on a Java-17 runner).
tasks.withType<JavaCompile>().configureEach { options.release.set(17) }
application { mainClass = "io.poly.candor.Candor" }
tasks.named<Test>("test") { useJUnitPlatform() }

// ⟨verify⟩ The shadowJar doubles as the `candor-java verify` DYNAMIC HONESTY ORACLE agent: the SAME fat jar
// is both the CLI (Main-Class) and a java.lang.instrument agent (Premain-Class). `candor-java verify` injects
// it into the target JVM via `-javaagent:<thisJar>=<includeFile>` (through JAVA_TOOL_OPTIONS), instruments the
// project methods the report names, and records the effect-bearing JDK calls they actually run — then checks
// `observed(f) ⊆ inferred(f) ∪ {Unknown}` against candor's STATIC report. Can-Retransform-Classes lets the
// agent (in principle) retransform already-loaded classes; the target's own classes load after premain so it
// is not strictly needed, but it is correct and cheap to declare. No second jar, no extra dependency — ASM 9.8
// is already bundled by the shadow plugin.
tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    manifest {
        attributes(
            "Premain-Class" to "io.poly.candor.verify.Agent",
            "Can-Retransform-Classes" to "true",
        )
    }
}

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

// SOUNDNESS R1094 — THE THREE DERIVED JDK INDEXES ARE CHECKED-IN INPUTS, NOT BUILD OUTPUTS.
// `jdk-supertypes.idx.gz` (the native-image JDK hierarchy, Cha.JdkSupers), `jdk-sams.idx.gz` (R191, Candor's SAM
// index) and `jdk-hof-invokes.idx.gz` (R237, the invoking-HOF index) used to be generated HERE, from `jrt:/` of the
// Gradle DAEMON's JVM — not the toolchain, not a named JDK. Measured 2026-10-09: the published v0.40.3 jar's three
// indexes are byte-identical to a build whose daemon ran Corretto 17.0.14 and differ from a JDK 21 build of the same
// commit, so the engine's knowledge of the JDK's functional interfaces and invoking HOFs was a property of the
// releaser's shell. They now live in src/main/resources/candor/, are written ONLY by soundness/jdk_index/derive.sh
// from the pinned Temurin 17/21/25 images in images.tsv (the same derivation, ported line for line to
// JdkIndexGen.java), and JdkIndexPinTest checks them against soundness/jdk_index/manifest.txt on every push.
// Nothing in this build reads the JDK it runs on to produce a resource. Do not add a task that does.

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
