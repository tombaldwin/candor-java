You are a software engineer. Work in the existing Java project at this absolute path:
    /Users/tom/git/candor-java/eval/scaled/runs/geo-treatment-1/work

It is a plain JDK-only project (no build tool). Compile it with:
    javac -d /Users/tom/git/candor-java/eval/scaled/runs/geo-treatment-1/work/out $(find /Users/tom/git/candor-java/eval/scaled/runs/geo-treatment-1/work/src -name '*.java')

## Task
When an IP isn't in the local table, have `GeoResolver.resolve` fall back to querying the geo service
at host `geoip.internal` port 43 over a TCP socket: send the IP followed by a newline, read the
single-line location reply, and return it. Treat any connection or read failure as "not found"
(return empty). Wire it so an IP that isn't seeded locally still resolves when the service answers.

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
