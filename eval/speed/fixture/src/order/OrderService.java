package order;

import cart.Cart;
import checkout.Checkout;
import money.Money;
import model.Line;
import pricing.Pricing;

import java.util.List;

/** Application service wiring pricing, cart and checkout for quotes and orders. */
public final class OrderService {
    private final Pricing pricing;
    private final Cart cart;
    private final Checkout checkoutFlow;

    public OrderService(Pricing pricing, Cart cart, Checkout checkoutFlow) {
        this.pricing = pricing;
        this.cart = cart;
        this.checkoutFlow = checkoutFlow;
    }

    public Money quoteOne(String sku, int qty) {
        return cart.lineTotal(sku, qty);
    }

    public List<Money> quoteMany(List<String> skus) {
        return pricing.quoteBulk(skus);
    }

    public Money checkout(List<Line> lines) {
        return checkoutFlow.place(lines);
    }
}
