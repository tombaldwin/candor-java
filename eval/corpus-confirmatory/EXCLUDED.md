# Excluded from the confirmatory corpus — the developmental set

These repositories are **deliberately not** in `manifest.tsv`. Each was used during the tool's development
to *drive a classifier fix* (the find→fix→re-verify reconcile loop of §7.3), so the classifier has been
tuned against them. Including them would re-measure developmental code and inflate the confirmatory result.
They remain valuable as the developmental record; they are just not evidence of *held-out* behavior.

| Repository | What it drove |
|---|---|
| `commons-io` | the transitive-oracle hold + the generic-override oracle key-format fix |
| `commons-dbcp2` | the super-call-through-generic-superclass vein (7 finds) |
| `commons-compress` | the synchronous-opaque-callback + filter-stream-delegate veins (4 finds) |
| `commons-vfs2` | the `doPrivileged`-invoker + active-I/O stream-delegate veins (4 finds) |
| `commons-exec` | the `Exec`/`Env`/`Clock` transitive hold |
| `commons-configuration2` | a re-run that surfaced only a disclosed model boundary |
| `zip4j` | the generic-override oracle false-positive fix |
| `jsoup` | the JVM `Net` language-arm datapoint |

If a confirmatory re-run of these is later wanted, it must be reported **separately** and labeled as a
re-run of developmental code, never folded into the held-out corpus table.
