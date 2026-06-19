package report;

import api.Api;
import money.Money;

import java.util.List;

/** Aggregates revenue across the featured catalogue. */
public final class Report {
    private final Api api;

    public Report(Api api) {
        this.api = api;
    }

    public Money dailyRevenue() {
        Money sum = new Money(0, "USD");
        for (Money m : api.listQuotes(List.of("WIDGET", "GADGET", "GIZMO"))) {
            sum = sum.plus(m);
        }
        return sum;
    }
}
