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
5. **Upload**: the Portal accepts a signed bundle. NOTE: the Portal **requires `.md5` and `.sha1`
   checksum files** for every artifact (jar/pom/sources/javadoc) alongside the `.asc` signatures, and
   `publishToMavenLocal` does NOT write checksums — so a bare zip of `~/.m2/...` is rejected on
   validation. Two working options:
   - **Recommended — let a plugin build a Central-compliant bundle:** add the `com.gradleup.nmcp`
     plugin and run `./gradlew publishAggregationToCentralPortal` (it emits signatures + checksums and
     uploads), or its `zipAggregation` task to produce a valid `bundle.zip` for manual upload.
   - **Manual:** after `publishToMavenLocal -PsigningInMemoryKey=…`, generate the checksums before
     zipping, e.g. `cd ~/.m2/repository/io/poly/candor/candor-java/X.Y.Z && for f in *.jar *.pom; do
     md5 -q "$f" > "$f.md5"; shasum "$f" | cut -d' ' -f1 > "$f.sha1"; done && zip -r bundle.zip .`
   → Portal → Publish → upload bundle.zip → release.
6. After Central is live, point `jbang-catalog.json` at the Central coordinates
   (`io.poly.candor:candor-java:X.Y.Z`) instead of the release URL.

NOT a Gradle plugin as the primary vehicle — candor-java analyzes compiled classes/jars; a build-gate
plugin is a later optional wrapper depending on the published core jar.
