You are a software engineer. Work in the existing Java project at this absolute path:
    /Users/tom/git/candor-java/eval/scaled/runs/catalog-treatment-2/work

It is a plain JDK-only project (no build tool). Compile it with:
    javac -d /Users/tom/git/candor-java/eval/scaled/runs/catalog-treatment-2/work/out $(find /Users/tom/git/candor-java/eval/scaled/runs/catalog-treatment-2/work/src -name '*.java')

## Task
On a cache miss, have `CatalogRepository.find` fall back to loading the product from disk at
`/var/cache/<id>` (the file holds one line `name,priceCents`; treat a missing or unreadable file as
"not found" and return empty). Wire it so an id that isn't in the in-memory store is still resolved
when a backing file exists.

Implement the feature by editing the project. Compile (command above) to confirm it builds.
Do not add external dependencies (the JDK is enough).

When done, end your reply with a section titled exactly '## Summary' — 3 to 6 sentences
describing what you changed and any consequences for the rest of the codebase that a
reviewer should know about.

## This project uses candor (an effect/capability checker)
A baseline of the pre-edit effects is saved at .candor/baseline.json. After you finish
editing, run this from the project directory:
    ./candor-diff.sh
It reports, per function, the effects each one gained versus the baseline. Read it and
fold anything relevant into your '## Summary'.
