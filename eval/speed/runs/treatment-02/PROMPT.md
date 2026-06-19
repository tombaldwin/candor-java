You are analyzing the Java project at this absolute path:
    /Users/tom/git/candor-java/eval/speed/runs/treatment-02/work

Question: if the function `pricing.Pricing.quote` gained the `Net` effect (it starts
performing network I/O), which OTHER functions in this project would transitively perform
`Net` as a result — i.e. every transitive caller of `Pricing.quote`? Be exhaustive: list
EVERY affected function across the whole project. Return ONLY a list of function names
(package.Type.method), one per line, no commentary.

candor is set up: an effect report is at `/Users/tom/git/candor-java/eval/speed/runs/treatment-02/work/.candor/report.json`, and the query tool
answers transitive callers directly. Run:
    java -jar /Users/tom/git/candor-java/build/libs/candor-java-0.5.42-all.jar callers /Users/tom/git/candor-java/eval/speed/runs/treatment-02/work/.candor/report.json pricing.Pricing.quote
(or `java -jar /Users/tom/git/candor-java/build/libs/candor-java-0.5.42-all.jar whatif /Users/tom/git/candor-java/eval/speed/runs/treatment-02/work/.candor/report.json pricing.Pricing.quote Net` for the blast radius). Use it.
