plugins { application }
repositories { mavenCentral() }
dependencies {
    implementation("org.ow2.asm:asm:9.7")
    implementation("org.ow2.asm:asm-tree:9.7")
    implementation("com.google.code.gson:gson:2.11.0")
}
java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }
application { mainClass = "candor.Candor" }
