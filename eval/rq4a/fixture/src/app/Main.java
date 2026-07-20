package app;

import infra.HttpRateSource;
import money.Money;
import pricing.Pricing;
import pricing.RateSource;

/** Composition root. The application layer is the ONE place allowed to name both the domain
 *  and the infrastructure: it constructs the concrete {@link HttpRateSource} adapter and injects
 *  it into {@link Pricing}. This is ordinary hexagonal/ports-and-adapters wiring — and it is
 *  exactly the wiring that hides the domain's network reach from an import-graph check. */
public final class Main {
    public static void main(String[] args) {
        RateSource rates = new HttpRateSource("rates.internal", 7070);
        Pricing pricing = new Pricing(rates);
        for (String sku : new String[] {"WIDGET", "GADGET"}) {
            Money q = pricing.quote(sku, "EUR");
            System.out.println(sku + ": " + q.amountMilli + " " + q.currency);
        }
    }
}
