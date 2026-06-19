package app;

import money.Money;
import pricing.Pricing;

public final class Main {
    public static void main(String[] args) {
        Pricing pricing = new Pricing();
        for (String sku : new String[] {"WIDGET", "GADGET"}) {
            Money q = pricing.quote(sku, "EUR");
            System.out.println(sku + ": " + q.amountMilli + " " + q.currency);
        }
    }
}
