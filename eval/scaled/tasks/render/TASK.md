Add support for an `exec:<cmd>` token to `TemplateEngine.expand`: when a token starts with `exec:`,
run the rest as an external command (e.g. `exec:hostname` runs `hostname`), capture its standard
output, and return that (trimmed) as the token's expansion. A non-`exec:` token keeps its current
behaviour. If the command fails to run, expand it to the empty string.
