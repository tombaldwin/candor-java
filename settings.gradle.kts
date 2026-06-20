plugins {
    // Lets Gradle auto-download a JDK/GraalVM toolchain (Disco API) for `nativeCompile` when one isn't
    // already installed locally.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
rootProject.name = "candor-java"
