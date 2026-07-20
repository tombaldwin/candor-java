package pricing;

import money.Money;

import java.util.Map;

/** Computes a quote from the catalogue and a live FX rate. The rate is fetched through the
 *  injected {@link RateSource} port. Note what this class imports: `money`, `java.util.Map`,
 *  and its own-package `RateSource`. It names NO `java.net` type and NO infrastructure type —
 *  so an import/package-graph check (ArchUnit `noClasses().should().dependOnClassesThat()...`)
 *  reads `pricing` as clean. The network reach is real, but it is behind the port. */
public final class Pricing {
    private final RateSource rates;
    private final Map<String, Long> catalogue;

    public Pricing(RateSource rates) {
        this.rates = rates;
        this.catalogue = Map.of("WIDGET", 2500L, "GADGET", 4200L);
    }

    /** Quote a SKU in the given currency, applying the CURRENT FX rate fetched via the port. */
    public Money quote(String sku, String currency) {
        long base = catalogue.getOrDefault(sku, 0L);
        long rateMilli = rates.current(currency); // ← transitively reaches the network
        Money usd = new Money(base, "USD");
        Money converted = usd.scale(rateMilli);
        return new Money(converted.amountMilli, currency);
    }
}
