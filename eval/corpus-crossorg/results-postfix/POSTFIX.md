# Post-fix verification — SEPARATE from the pre-registered table

`PREREG.md` freezes the confirmatory run: findings are **recorded, not repaired**, and the table in
`results/` is the result of the hash-pinned engine `e60655c6…` whatever it says. That table still reports
HikariCP's **2 violations** and always will.

This directory is the **separate, later** result the pre-registration anticipates ("any fix is a separate,
later effort with its own separate result; it does not amend this table"). It re-runs the same corpus,
same suite, same method, on an engine that has had the vein closed.

## Result: the falsifier's own catch, closed and re-verified

| | pre-registered run (engine `e60655c6…`) | post-fix (vein closed) |
|---|---|---|
| executed + checked | 74 | 74 |
| sound-complete (`D = ∅`) | 25 | **27** |
| disclosed-partial | 47 | 47 |
| **cardinal-sin violations** | **2** | **0** |
| `honestyInvariantHolds` | **false** | **true** |
| attributionComplete | true | true |

The two violating frames — `ConcurrentBag.remove` and `.unreserve` — moved into **`soundCompleteOk`**
(25 → 27), not into `disclosedPartial`. That direction matters: the fix *resolved* the effect (they now
carry `Clock`), it did not paper over the miss by disclosing `Unknown` on them. `disclosedPartial` is
unchanged at 47, so nothing else was pushed into disclosure to buy the result.

## The fix

Parameterized logging (`LOGGER.warn("...{}", entry)`) added to candor-java's implicit-contract-reentry
sink table. The mechanism already existed for `String.format` / `StringBuilder.append(Object)` /
`println(Object)` — it CHA-dispatches `toString` over the argument's declared type and edges to any LOCAL
override — and logging facades were simply absent from the table. Matched by level-name plus an
`Object`-bearing descriptor, owner-agnostically, because the bytecode owner is whichever `Logger`
interface the project imported.

## Fabrication gate

A/B on a real 18.7k-function log-heavy application (uflexi): **8939 effectful functions before, 8939
after, 0 functions changed.** The mechanism contributes nothing unless the argument's declared type has a
local, effectful `toString`, so String/boxed/library arguments — the overwhelming majority of log
arguments — edge nowhere. Suite 436 green, with a regression test pinning all three directions
(effectful `toString` caught; pure `toString` silent; a level method with no `Object` argument is not a
sink).
