You are analyzing the Java project at this absolute path:
    /Users/tom/git/candor-java/eval/speed/runs/control-02/work

Question: if the function `pricing.Pricing.quote` gained the `Net` effect (it starts
performing network I/O), which OTHER functions in this project would transitively perform
`Net` as a result — i.e. every transitive caller of `Pricing.quote`? Be exhaustive: list
EVERY affected function across the whole project. Return ONLY a list of function names
(package.Type.method), one per line, no commentary.

Work from the source code.
