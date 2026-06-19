package pricing;

import money.Money;

import java.util.Map;

/** Computes a quote from the catalogue and an FX rate. The rate is held here and
 *  can be updated with {@link #setRate}. */
public final class Pricing {
    private long rateMilli;
    private final Map<String, Long> catalogue;

    public Pricing() {
        this.rateMilli = 1000; // parity until a rate is set
        this.catalogue = Map.of("WIDGET", 2500L, "GADGET", 4200L);
    }

    public void setRate(long rateMilli) {
        this.rateMilli = rateMilli;
    }

    /** Quote a SKU in the given currency, applying the current FX rate. */
    public Money quote(String sku, String currency) {
        long base = catalogue.getOrDefault(sku, 0L);
        Money usd = new Money(base, "USD");
        Money converted = usd.scale(rateMilli);
        return new Money(converted.amountMilli, currency);
    }
}
