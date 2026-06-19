package pricing;

import money.Money;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Looks up the base price for a SKU from the catalogue. */
public final class Pricing {
    private final Map<String, Long> catalogue =
            Map.of("WIDGET", 2500L, "GADGET", 4200L, "GIZMO", 999L);

    public Money quote(String sku) {
        return new Money(catalogue.getOrDefault(sku, 0L), "USD");
    }

    public List<Money> quoteBulk(List<String> skus) {
        List<Money> out = new ArrayList<>();
        for (String s : skus) {
            out.add(quote(s));
        }
        return out;
    }
}
