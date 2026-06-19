# quotes

A small program that computes price quotes for a fixed catalogue.

## Modules

- `money` — value types (`Money`) and arithmetic on amounts.
- `pricing` — computes a quote from the catalogue and an FX rate. The rate is
  held in `Pricing` and can be updated with `setRate`.
- `app` — the entry point; prints one quote per SKU.

## Building & running

```
javac -d out $(find src -name '*.java')
java -cp out app.Main
```
