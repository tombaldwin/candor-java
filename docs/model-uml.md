# candor-java domain model — annotated UML

The `io.poly.candor.model` package: the spec's nouns as types (candor-spec [SPEC.md](https://github.com/tombaldwin/candor-spec/blob/main/SPEC.md) /
[SEMANTICS.md](https://github.com/tombaldwin/candor-spec/blob/main/SEMANTICS.md) / [MODEL.md](https://github.com/tombaldwin/candor-spec/blob/main/MODEL.md)).
Produced by `ReportWriter` (analyzer) and consumed by `Query` — the same types on both sides, via one
`ReportJson` (de)serializer.

> Rendered: [model-uml.svg](model-uml.svg) (open raw for a crisp, zoomable view). Mermaid source below.

```mermaid
classDiagram
    direction LR

    class Report {
        <<record>>
        +Provenance candor
        +List~String~ packages
        +List~Effector~ functions
    }
    class Provenance {
        <<record>>
        +String version
        +String toolchain
        +String spec
    }
    class Effector {
        <<record>>
        +String fn
        +String loc
        +EffectSet inferred
        +EffectSet direct
        +EffectSet declared
        +EffectSet undeclared
        +EffectSet overdeclared
        +boolean entryPoint
        +boolean unresolved
        +EffectorKind kind
        +List~UnknownReason~ unknownWhy
        +String hash
        +List~String~ calls
        +List~String~ invisible
        +List~String~ fs
        +List~String~ hosts
        +List~String~ cmds
        +List~String~ paths
        +List~String~ tables
    }
    class EffectSet {
        -EnumSet~Effect~ set
        +join(EffectSet) EffectSet
        +contains(Effect) boolean
        +hasUnknown() boolean
        +toNames() List~String~
    }
    class Effect {
        <<enumeration>>
        NET FS DB EXEC ENV
        CLOCK IPC LOG RAND CLIPBOARD
        UNKNOWN
        +specName() String
        +isBoundary() boolean
        +isTrustMarker() boolean
        +fromSpecName(String)$ Effect
        +KNOWN / AMBIENT_AUTHORITY / INJECTION$ Set~Effect~
    }
    class EffectorKind {
        <<enumeration>>
        FUNCTION INITIALIZER ACCESSOR
        EXPORT AGENT COMMAND SKILL
        CRON SESSION HOOKS
        +wireName() String
        +fromWire(String)$ EffectorKind
    }
    class UnknownReason {
        <<record>>
        +String prefix
        +String detail
        +kind() Kind
        +format() String
        +parse(String)$ UnknownReason
    }
    class ReasonKind {
        <<enumeration>>
        REFLECT NATIVE DISPATCH
        CALLBACK TASK_HANDOFF INDY
        +prefix() String
    }

    class PolicyRule {
        <<sealed interface>>
    }
    class Deny {
        <<record>>
        +EffectSet effects
        +String scope
        +String src
    }
    class Allow {
        <<record>>
        +Effect effect
        +String scope
        +Set~String~ values
        +String src
    }
    class Forbid {
        <<record>>
        +String from
        +String to
    }

    class Diagnostic {
        <<record>>
        +DiagnosticCode code
        +String message
        +render() String
    }
    class DiagnosticCode {
        <<enumeration>>
        AS_EFF_001 .. AS_EFF_009
        +code() String
        +bracket() String
    }
    class Mode {
        <<enumeration>>
        AUDIT CONFORMANCE NO_AMBIENT
        BASELINE POLICY TAINT
        +envVar() String
    }
    class ReportJson {
        <<utility>>
        +serialize(Report)$ String
        +parseEntries(JsonArray)$ List~Effector~
    }

    Report o-- "1" Provenance : candor
    Report o-- "*" Effector : functions
    Effector o-- "5" EffectSet : inferred/direct/declared/undeclared/overdeclared
    Effector --> EffectorKind : kind
    Effector o-- "*" UnknownReason : unknownWhy
    EffectSet o-- "*" Effect
    UnknownReason --> ReasonKind : kind()
    PolicyRule <|.. Deny
    PolicyRule <|.. Allow
    PolicyRule <|.. Forbid
    Deny --> EffectSet : effects
    Allow --> Effect : effect
    Diagnostic --> DiagnosticCode : code
    ReportJson ..> Report : serialize / parse

    note for Effect "spec §1 — the closed effect vocabulary + Unknown (the §4 trust marker, not an effect). Declared in spec-name order."
    note for EffectSet "SEMANTICS §1 — a lattice element (join = ∪). toNames() emits spec-name-sorted: the ONE wire path, and the byte-identity invariant."
    note for Effector "spec §2 — the per-unit entry ('effector' = the spec's 'unit'). The wire field stays fn; serialized by ReportJson, not by reflecting the record (conditional omission)."
    note for UnknownReason "spec §4 — a kind:detail disclosure tag. Stores the raw prefix so any (incl. foreign) tag round-trips; kind() is derived."
    note for ReasonKind "spec §4 canonical: reflect/native/dispatch/callback. task-handoff/indy are candor-java extras (tracked follow-up)."
    note for Report "spec §2 — the { candor, packages, functions } envelope."
    note for Provenance "spec §2.1 — the candor header (build id + toolchain + contract version)."
    note for PolicyRule "spec §6.2 — the deny/allow/forbid DSL, parsed into a sealed family."
    note for DiagnosticCode "spec §6 — AS-EFF-001..010 (candor-java emits 001–009)."
    note for Mode "spec §3 — analysis modes, each gate selected by its env var."
```

## Reading the diagram

- **The report spine** `Report → Effector → EffectSet → Effect` is the data an analysis produces and a
  query consumes. `Report` (the §2 envelope) holds a `Provenance` header and the `Effector`s; each
  `Effector` carries five `EffectSet`s (the conformance axes), its `EffectorKind`, and its
  `UnknownReason` disclosure list.
- **`EffectSet.toNames()` is the single serialization path** and always emits spec-name-sorted. Because
  every effect→wire path goes through it, the internal representation (an `EnumSet<Effect>`) is free to
  differ from the wire without changing a byte — this is what made full internal adoption safe.
- **`PolicyRule` is a sealed family** (`Deny`/`Allow`/`Forbid`) — the parsed §6.2 DSL, exhaustively
  switchable. `Diagnostic`/`DiagnosticCode` type the §6 AS-EFF findings; `Mode` types the §3 gate modes.
- **`ReportJson` is the one (de)serializer** — `ReportWriter` builds a `Report` and serializes it;
  `Query` parses reports back into `Effector`s. Wire field names (`fn`, `unitKind`, `packages`) are
  historical and unchanged.

The cross-engine realization of these same concepts is in candor-spec/MODEL.md — a shared *vocabulary*,
each engine deriving it independently from the spec (not shared code).
