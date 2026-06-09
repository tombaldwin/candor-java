# candor-java `unknownWhy` sweep at scale (gradle cache)

**Newly possible** because the jar-input bug was fixed (`e0c7582`) — candor-java can now analyse `.jar`
archives, so the gradle cache (449 jars) became a standing corpus, the JVM analog of the cargo registry.

**Question.** On uFlexi, the `unknownWhy` origin tag revealed that most `Unknown`s were *resolvable
dispatch* (→ two fixes). Does the same class of resolvable-but-unresolved `Unknown` hide at scale across
diverse real JVM libraries? Tag every directly-introduced `Unknown` (`reflect:` / `native:` / `dispatch:`)
and hunt recurring `dispatch:` targets that appear *inside a library's own jar* (where the impls are
present → a resolution bug, not correct cross-jar invisibility).

**Method.** Ran candor-java over all 449 cache jars (393,490 functions), tallied `unknownWhy` origins,
ranked recurring `dispatch:` targets.

**Finding — a 36%-of-dispatch precision bug.** The tally was dominated by **byte-buddy** types
(`MethodList.filter` ×605, `getOnly`, `MethodDescription.isStatic`, `FieldList.*`, `TypeDescription.*`) —
appearing **inside byte-buddy's own jar**, where the implementations exist. Root cause: the ubiquitous
`Foo` interface / `Foo$AbstractBase` library idiom — `filter` is declared abstract on the interface and
implemented concretely in a **grandparent** (`FilterableList$AbstractBase`), inherited by the concrete
subtypes without redeclaration. `chaTargets` checked each subtype's *own* declaration and walked *up from
the interface*, but never resolved a subtype's *inherited* concrete impl (reached by going **down** owner→
subtype, then **up** the subtype's chain). These `filter`/`getOnly` methods are pure, so it was **false
`Unknown`s flooding the report, not hidden effects** — a precision bug.

**Fix (`62352e6`).** `chaTargets` now resolves a non-declaring subtype's inherited impl via its
superchain (`nearestConcreteSuper`). Strictly more resolution = more edges = sound (verified: soundness
fuzzer 40/0 with teeth on default/inherited/super/iface; smoke 105). New regression for the pattern.

**Result (before → after, full 449-jar corpus):**

| | before | after | |
|---|---:|---:|---|
| functions w/ `unknownWhy` | 14,559 | 11,437 | **−21%** |
| `dispatch:` tags | 14,220 | 9,103 | **−36%** (5,117 resolved) |
| `reflect:` tags | 5,445 | 5,445 | 0% (irreducible — correct) |
| `native:` tags | 366 | 366 | 0% (irreducible — correct) |

The fix generalises far beyond byte-buddy: *every* library using the `AbstractList`/`AbstractBase` idiom
was over-reporting `Unknown`.

**Residual is honest.** The top remaining `dispatch:` unknowns were triaged to ground truth and are
correct: Hibernate's `AbstractDelegating*.getThis` (an abstract *delegating-wrapper* extension point —
the concrete `getThis` is user-supplied, no in-jar impl), `com.sun.jna…Kernel32.GetLastError` (a native
Windows API), `commons-io IOFunction.apply` (a user lambda), Hibernate bytecode-enhancement synthetics.
`reflect:`/`native:` unchanged confirms candor isn't over-resolving the genuinely-opaque.

**Robustness.** Across the 449 jars: 0 crashes, multi-release (`META-INF/versions/`) + `module-info`
handled benignly. The gradle cache is now a standing candor-java validation corpus.
