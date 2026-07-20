package app;

import money.Money;
import pricing.Pricing;
import pricing.RateSource;

/** Composition root that wires the adapter by REFLECTION (a DI-container / plugin pattern): the concrete
 *  RateSource class name comes from configuration, and the instance is built with Class.forName(...)
 *  .getDeclaredConstructor().newInstance(). No `new HttpRateSource()` / `new PureRateSource()` appears in
 *  the program, so a points-to call graph has no allocation to flow into Pricing's RateSource field. */
public final class Main {
    public static void main(String[] args) throws Exception {
        String impl = System.getProperty("rate.impl", "infra.HttpRateSource");
        RateSource rates = (RateSource) Class.forName(impl)
                .getDeclaredConstructor().newInstance();
        Pricing pricing = new Pricing(rates);
        for (String sku : new String[] {"WIDGET", "GADGET"}) {
            Money q = pricing.quote(sku, "EUR");
            System.out.println(sku + ": " + q.amountMilli + " " + q.currency);
        }
    }
}
