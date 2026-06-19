package api;

import money.Money;
import model.Line;
import order.OrderService;

import java.util.List;

/** Request entry points for quotes and checkout. */
public final class Api {
    private final OrderService orders;

    public Api(OrderService orders) {
        this.orders = orders;
    }

    public Money getQuote(String sku, int qty) {
        return orders.quoteOne(sku, qty);
    }

    public List<Money> listQuotes(List<String> skus) {
        return orders.quoteMany(skus);
    }

    public Money postCheckout(List<Line> lines) {
        return orders.checkout(lines);
    }
}
