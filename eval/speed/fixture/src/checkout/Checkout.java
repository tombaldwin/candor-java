package checkout;

import cart.Cart;
import discount.Discount;
import money.Money;
import model.Line;

import java.util.List;

/** Reviews and places an order, applying the cart total and discount. */
public final class Checkout {
    private final Cart cart;
    private final Discount discount;

    public Checkout(Cart cart, Discount discount) {
        this.cart = cart;
        this.discount = discount;
    }

    public Money review(List<Line> lines) {
        Money total = cart.total(lines);
        Money disc = discount.forCart(lines);
        return new Money(total.amountCents - disc.amountCents, total.currency);
    }

    public Money place(List<Line> lines) {
        return review(lines);
    }
}
