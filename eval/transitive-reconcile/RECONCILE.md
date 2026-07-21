# The transitive reconcile-against-reality result (RQ1, §7.1 Part F)

The transitive `candor verify` oracle, run under single-JVM ConsoleLauncher attribution over independently-
authored Apache Commons libraries, caught **15 real silent under-reports** on code candor's authors did not
write and drove **5 classifier fixes** (plus one scoping-class catch closed by a value-provenance
disclosure). This file is the provenance ledger the paper's Part F rests on: what each catch was, the fix
commit that closed it, the regression test that gates it, and how to **re-witness** it.

## How to reproduce

- **The holds (push-button, current engine).** `bash run.sh` clones the six libraries at the pinned tags,
  builds them, and runs the transitive oracle. On the current (post-fix) engine every fix-driving repo now
  **holds** (0 undisclosed violations) — the fixes are in the engine, so the previously-silent frames now
  resolve or disclose. `results/SUMMARY.tsv` is the per-repo record.
- **The catches (re-witness, pre-fix engine).** Each catch is a frame that read *pure* on the engine
  **before** its fix commit. To re-witness one: check out candor-java at the vein's *pre-fix* commit (the
  parent of the fix commit below), rebuild the `-all.jar`, and re-run only that repo
  (`CANDOR_JAR=… bash run.sh commons-dbcp2`). The previously-silent caller then flags as a violation.
- **The catches (no re-run, always).** Each fix ships with a per-vein regression test (below). A pre-fix
  engine is exactly what that test fails; a passing test on the current engine certifies the vein is closed.
  This is the standing attestation the fixes are real and the veins were live.

The **holds** are fully reproducible from this artifact today; the **catches** are attested by the pinned
pre-fix commits + the regression gates, and re-witnessable by rebuilding the pre-fix engine. We do not ship
pre-fix `-all.jar`s (they are rebuildable from the pinned commits); §DAS states this scope.

## The 15 catches, by vein (dbcp2 / compress / vfs2)

| # | corpus | vein | shape (read *pure*, reaches an effect) | fix (candor-java) | regression test |
|---|---|---|---|---|---|
| 1–5 | commons-dbcp2 | **super-call through a generic intermediate superclass** | `PoolableConnection.setLastUsed`/`activate`/… reach `Instant.now()` (`Clock`) via `super.method()` resolving through `DelegatingConnection<Connection> extends AbandonedTrace` — the `super` edge dropped to a non-existent node | resolve `super.m()` to the **nearest superclass that declares** `m` (as the virtual path does); gated | `SoundnessSweepTest` super-call-through-generic-superclass case |
| 6–9 | commons-compress | **synchronous opaque-callback HOF** | `ArchiveInputStream.forEach` → `iterator().forEachRemaining(param)` read pure — an opaque `IOConsumer` handed to a *synchronous* invoking HOF was neither edged nor disclosed | disclose `Unknown` for `forEach`/`forEachRemaining`/`ifPresent` opaque args (JDK + commons alike); additive, opaque-args-only | `StructuralDispatchTest.syncCallbackInvokerOwnerAgnosticListForEach` (`7047572`) |
| 6–9 | commons-compress | **filter-stream `close`/`flush` delegate** | `CompressFilterOutputStream.close` / `ZipArchiveOutputStream.destroy` → `super.close()` delegates to a wrapped sink of unknown concrete type — the deferred close read pure | wrapped-sink `close`/`flush` → `Unknown` (disclose, never fabricate `Fs`: the sink may be in-memory) | `StructuralDispatchTest.bufferedAndFilterStream…` (`3353860`) |
| 10–13 | commons-vfs2 | **`doPrivileged` as a synchronous invoking HOF** | `PrivilegedFileReplicator.init`/`replicateFile` → `AccessController.doPrivileged(action)` read pure — `doPrivileged` was not modelled as *invoking* the `PrivilegedAction`'s `run()`, orphaning the replicator's `Net`/`Fs` | model `doPrivileged` as `isInvokingHof`; add `PrivilegedAction`/`PrivilegedExceptionAction` as SAM invokers | `SoundnessSweepTest.doPrivilegedActionRunsSynchronouslyAndPropagates` (`3a63266`) |
| 10–13 | commons-vfs2 | **active-I/O stream-delegate** | `MonitorOutputStream.write`/`flush` → `super.write` delegates a `RAM`-sink's `Clock` — the active-I/O methods (not just close/flush) also delegate to the wrapped sink | extend the wrapped-sink `Unknown` rule to read/write/skip and the `Buffered*` bases; self-limiting (only the `super.`-from-subclass call matches) | wrapped-sink active-I/O case (`2433db6`) |

The five veins map to **five fixes**; the per-corpus catch counts are **7 (dbcp2) + 4 (compress) + 4 (vfs2) = 15**.

## Closure status (13 closed, 2 open)

- **13 of 15 closed** — each fix is additive/opaque-only, zero-fabrication on its A/B, conformance-clean,
  and regression-gated; re-verified to **0 remaining violations** on each corpus's suite.
- **2 open** — dbcp2's `_pool.borrowObject → activateObject` **framework-callback (A3)** residual: the pool
  hands the connection back through a framework callback the modular analysis does not follow. It still reads
  pure at the frozen build; it is a named open classifier work-item awaiting framework modelling, **not** a
  model boundary (no R-entry, no §8.5 carve-out) — but a knowingly-silent-in-report site until the fix ships.

## The scoping-class catch (readFully — separate from the 15)

`compress`'s `ZipArchiveInputStream.readFully(byte[],int)` reads a **caller-opened** stream via
`IOUtils.read`. Under charge-at-creation this is sound when the opener is analyzed, an under-report only under
a **library-scoped** analyzed set (the convergence run's config — the opener is the unanalyzed test suite),
where it *was* a witnessed under-report. Distinct in cause from the 15 classifier veins (a source/sink
*scoping* consequence, not a classifier bug); closed by a **value-provenance disclosure** that reads `Unknown`
when a consuming utility reads a stream the method did not itself open (regression
`externalStreamReadViaUtilityIsUnknownButInScopeOpenStaysPure`; the in-function open stays precise).

## The two held + one convergence run

`commons-io` and `commons-exec` **held with zero finds** (272 fns checked, attribution-complete).
`commons-configuration2` was a post-fix **convergence run** (130 fns, no new classifier vein); its
`CatalogResolver.getResolver` reaches `Net` only through an *unmodelled third-party* XML-catalog constructor —
an **uncovered** reach candor discloses via the coverage envelope, out-of-scope for H by the covered-set
scoping of §3.4, a disclosed boundary rather than a false all-clear.
