# Ground truth — geo (Net)

**Effect gained:** `Net`. **Edited function:** `geo.GeoResolver.resolve`.

The natural implementation opens a `java.net.Socket` to `geoip.internal:43` on a local-table miss.
That makes the resolve perform network I/O, which propagates transitively to **every caller** — so a
`resolve` that callers assume is a cheap in-memory table lookup now does a network round-trip on each
call, including `GeoReport.summary`.

**Propagation set (7 functions, across 6 files)** — verified by applying the canonical edit and
running `candor diff cur.json baseline.json` (not by hand):

- `geo.GeoResolver.resolve`        (GeoResolver.java — the source)
- `geo.GeoService.locate`          (GeoService.java)
- `geo.GeoService.batch`           (GeoService.java)
- `geo.GeoController.lookupOne`    (GeoController.java)
- `geo.GeoController.lookupMany`   (GeoController.java)
- `geo.GeoReport.summary`          (GeoReport.java)
- `geo.Main.main`                  (Main.java)

The non-local consequence under test: callers in `GeoService`, `GeoController`, `GeoReport`, `Main` —
not just `resolve` — now perform `Net`.

Mirrors the Rust `geoip` task (`candor-rust/eval/scaled/tasks-v2/geoip`) for cross-engine
comparability.
