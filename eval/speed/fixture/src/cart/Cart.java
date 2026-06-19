package cart;

import money.Money;
import model.Line;
import pricing.Pricing;

import java.util.List;

/** Computes line totals and cart subtotals/totals from the pricing engine. */
public final class Cart {
    private final Pricing pricing;

    public Cart(Pricing pricing) {
        this.pricing = pricing;
    }

    public Money lineTotal(String sku, int qty) {
        return pricing.quote(sku).times(qty);
    }

    public Money subtotal(List<Line> lines) {
        Money sum = new Money(0, "USD");
        for (Line l : lines) {
            sum = sum.plus(lineTotal(l.sku, l.qty));
        }
        return sum;
    }

    public Money total(List<Line> lines) {
        Money sub = subtotal(lines);
        return sub.plus(new Money(sub.amountCents / 10, sub.currency)); // +10% tax
    }
}
