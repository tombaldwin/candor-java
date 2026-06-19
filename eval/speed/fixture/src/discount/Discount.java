package discount;

import cart.Cart;
import money.Money;
import model.Line;

import java.util.List;

/** Computes a cart-level discount from the subtotal. */
public final class Discount {
    private final Cart cart;

    public Discount(Cart cart) {
        this.cart = cart;
    }

    public Money forCart(List<Line> lines) {
        Money sub = cart.subtotal(lines);
        return new Money(sub.amountCents / 20, sub.currency); // 5% discount
    }
}
