# Ground truth — render (Exec)

**Effect gained:** `Exec`. **Edited function:** `render.TemplateEngine.expand`.

The natural implementation runs an external command via `java.lang.ProcessBuilder` for an
`exec:<cmd>` token. That makes the expand perform process execution, which propagates transitively to
**every caller** — so an `expand` that callers assume is a pure string substitution now spawns a
process on each call, including `RenderReport.buildAll`.

**Propagation set (7 functions, across 5 files)** — verified by applying the canonical edit and
running `candor diff cur.json baseline.json` (not by hand):

- `render.TemplateEngine.expand`           (TemplateEngine.java — the source)
- `render.Page.renderToken`                (Page.java)
- `render.Page.render`                      (Page.java)
- `render.RenderController.renderOne`       (RenderController.java)
- `render.RenderController.renderMany`      (RenderController.java)
- `render.RenderReport.buildAll`            (RenderReport.java)
- `render.Main.main`                        (Main.java)

The non-local consequence under test: callers in `Page`, `RenderController`, `RenderReport`, `Main` —
not just `expand` — now perform `Exec`.

Mirrors the Rust `renderer` task (`candor-rust/eval/scaled/tasks-v2/renderer`) for cross-engine
comparability.
