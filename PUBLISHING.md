# Publishing candor-java

Three-axis versioning (candor-spec §2.1): `spec` (0.3, the contract) / `version` (git hash, baked at
build) / **this file's concern: the release semver** (`version=` in build.gradle.kts).

## Zero-install today (live)

- **GitHub Release** `vX.Y.Z` carries the fat jar (`candor-java-X.Y.Z-all.jar`, ~520K, bundles ASM+GSON):
  `java -jar candor-java-X.Y.Z-all.jar <classes-or-jar> [--json out.json]`
- **jbang** (the `cargo install` analog) via the in-repo catalog (`jbang-catalog.json`):
  ```sh
  jbang candor@tombaldwin/candor-java <classes-or-jar> --json out.json
  ```

## Release steps (each version)

1. Bump `version =` in build.gradle.kts; commit + push.
2. `./gradlew clean shadowJar publishToMavenLocal` — verifies the full artifact set
   (main/sources/javadoc/all jars + POM) builds.
3. `gh release create vX.Y.Z build/libs/candor-java-X.Y.Z-all.jar --title "candor-java X.Y.Z" --notes "…"`
4. Update `jbang-catalog.json`'s `script-ref` to the new release URL; commit + push.

## Maven Central (one-time setup — requires Tom; ~10 minutes)

The Gradle side is DONE (maven-publish + signing config, Central-compliant POM, sources/javadoc jars —
`publishToMavenLocal` verified). What only you can do:

1. **Central Portal account**: https://central.sonatype.com → sign in (GitHub SSO works).
2. **Claim the namespace** `io.poly.candor`: Portal → Namespaces → add `io.poly.candor` → verify via a
   DNS TXT record on `poly.io` (the Portal shows the exact token). (Alternative if poly.io DNS is a
   hassle: claim `io.github.tombaldwin` instead — auto-verified via GitHub; then change `group =`.)
3. **GPG key**: `gpg --gen-key` (use tom@polymorphism.co.uk), publish it:
   `gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>`.
4. **Credentials** in `~/.gradle/gradle.properties`:
   ```
   signingInMemoryKey=<ascii-armored private key, \n-escaped>   # gpg --export-secret-keys --armor <KEYID>
   signingInMemoryKeyPassword=<passphrase>
   centralPortalUsername=<portal token user>
   centralPortalPassword=<portal token pass>
   ```
5. **Upload**: the Portal accepts a signed bundle. Simplest path:
   `./gradlew publishToMavenLocal -PsigningInMemoryKey=… && cd ~/.m2/repository && zip -r bundle.zip io/poly/candor/candor-java/X.Y.Z`
   → Portal → Publish → upload bundle.zip → release. (If releases become frequent, add the
   `com.gradleup.nmcp` Portal-publishing plugin to automate this step.)
6. After Central is live, point `jbang-catalog.json` at the Central coordinates
   (`io.poly.candor:candor-java:X.Y.Z`) instead of the release URL.

NOT a Gradle plugin as the primary vehicle — candor-java analyzes compiled classes/jars; a build-gate
plugin is a later optional wrapper depending on the published core jar.
