# OpenRewrite — semantic refactoring for candor-java

OpenRewrite is wired in (`org.openrewrite.rewrite` Gradle plugin) as the tool for **mechanical or
large-scale source refactors** where a regex is unsafe and a hand pass is error-prone. Unlike `sed`/`perl`,
OpenRewrite parses with **full type attribution**, so a recipe rewrites only the references that actually
resolve to the named type/method — never a same-named local, a method on another class, or text inside a
string literal or comment.

## When to reach for it (vs. the alternatives)

| Change | Best tool | Why |
|---|---|---|
| Uniform, unambiguous token swap (e.g. `ctx.` → `ctx().`) | `perl`/`sed` + the compiler as backstop | The token has one meaning; the compiler catches any miss. Zero setup. (This is how LB-1b was done.) |
| Type/signature-sensitive edit, or a same-named token with >1 meaning | **OpenRewrite** or IntelliJ refactor | Needs scope/type analysis to avoid touching the wrong `ctx`/`save()`/etc. |
| Signature change threaded through call sites (Change Signature / Introduce Parameter) | **OpenRewrite** or IntelliJ | A text threader gets call-site arg insertion wrong (this is what failed the first LB-1b attempt). |
| Standing / repeatable migration you want re-runnable in CI | **OpenRewrite custom recipe** | Idempotent, testable, reviewable as code. |

Note OpenRewrite is JVM-only — it does not help the sibling engines (candor-rust/ts/swift). For those:
`ast-grep`/`comby` (syntactic, cross-language) or each language's own (`ts-morph`, `rust-analyzer`).

## How to run a refactor

1. Define the recipe in `rewrite.yml` (declarative — compose `ChangeType`, `ChangeMethodName`,
   `ChangeMethodInvocation`, … ; the file has a commented template) **or** name a built-in recipe.
2. Opt it in: `rewrite { activeRecipe("io.poly.candor.YourRecipe") }` in `build.gradle.kts`.
   By default **no recipe is active**, so `rewriteRun` is a no-op until you do this — deliberate, so a
   stray run can't churn the tree.
3. **Preview:** `./gradlew rewriteDryRun` — writes `build/reports/rewrite/rewrite.patch`, changes nothing.
   Read the patch.
4. **Apply:** `./gradlew rewriteRun`.
5. **Gate (mandatory after any apply):** the same battery every behavioral change runs —
   `./gradlew test`, the byte-identity oracle (pc/jsoup/gson `functions[]` identical),
   `bash soundness/run.sh`, `CJ=<jar> python3 soundness/kappa_libs_probe.py`, and
   `candor-spec/conformance/run.sh`. OpenRewrite changes *source*, not behavior — but the gate is what
   proves that.

## Review the dry-run; do not blind-apply

A recipe can do more than its name suggests. Concrete example from wiring this up:
`org.openrewrite.java.RemoveUnusedImports` — the canonical demonstrator — not only removes unused imports
but **unfolds wildcard imports** (`import org.objectweb.asm.tree.*;` → explicit class imports). candor-java
deliberately uses wildcard imports, so applying it would churn ~50 files against our style. The dry-run
surfaced this; we left the recipe inactive. That is the workflow working as intended: **preview, judge
against conventions, then decide** — the same reason we don't auto-apply a regex without reading the diff.
