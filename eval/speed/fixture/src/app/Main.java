package app;

import admin.Admin;
import api.Api;
import cart.Cart;
import checkout.Checkout;
import discount.Discount;
import model.Line;
import order.OrderService;
import pricing.Pricing;
import report.Report;

import java.util.List;

public final class Main {
    public static void main(String[] args) {
        Pricing pricing = new Pricing();
        Cart cart = new Cart(pricing);
        Discount discount = new Discount(cart);
        Checkout checkout = new Checkout(cart, discount);
        OrderService orders = new OrderService(pricing, cart, checkout);
        Api api = new Api(orders);
        Report report = new Report(api);
        Admin admin = new Admin(orders);

        System.out.println(api.getQuote("WIDGET", 3).amountCents);
        System.out.println(api.postCheckout(List.of(new Line("WIDGET", 2), new Line("GADGET", 1))).amountCents);
        System.out.println(report.dailyRevenue().amountCents);
        admin.recomputePrices(List.of("WIDGET", "GADGET"));
    }
}
