# Ground truth — catalog (Fs)

**Effect gained:** `Fs` (read). **Edited function:** `catalog.CatalogRepository.find`.

The natural implementation adds `java.nio.file.Files.readString` on a cache miss (load the product
from `/var/cache/<id>`). That makes the read perform filesystem I/O, which propagates transitively to
**every caller** — so a `find` that callers assume is a cheap in-memory lookup now does disk I/O on
each call, including `DashboardReport.build` (a refresh on a tight interval).

**Propagation set (7 functions, across 6 files)** — verified by applying the canonical edit and
running `candor diff cur.json baseline.json` (not by hand):

- `catalog.CatalogRepository.find`        (CatalogRepository.java — the source)
- `catalog.CatalogService.lookup`         (CatalogService.java)
- `catalog.CatalogService.batch`          (CatalogService.java)
- `catalog.CatalogController.getOne`      (CatalogController.java)
- `catalog.CatalogController.getMany`     (CatalogController.java)
- `catalog.DashboardReport.build`         (DashboardReport.java)
- `catalog.Main.main`                     (Main.java)

The non-local consequence under test: callers in `CatalogService`, `CatalogController`,
`DashboardReport`, `Main` — not just `find` — now perform `Fs`.

Mirrors the Rust `minicache` task (`candor-rust/eval/scaled/tasks-v2/minicache`) for cross-engine
comparability.
