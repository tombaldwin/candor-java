package catalog;

import java.util.List;

/** Builds the featured-products dashboard line. */
public final class DashboardReport {
    private final CatalogController controller;

    public DashboardReport(CatalogController controller) {
        this.controller = controller;
    }

    public String build() {
        List<Product> featured = controller.getMany(List.of("sku-1", "sku-2", "sku-3"));
        StringBuilder sb = new StringBuilder();
        for (Product p : featured) {
            sb.append(p.name).append(' ');
        }
        return sb.toString().trim();
    }
}
