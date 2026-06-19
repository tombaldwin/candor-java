package admin;

import order.OrderService;

import java.util.List;

/** Administrative recompute of cached prices. */
public final class Admin {
    private final OrderService orders;

    public Admin(OrderService orders) {
        this.orders = orders;
    }

    public void recomputePrices(List<String> skus) {
        orders.quoteMany(skus);
    }
}
