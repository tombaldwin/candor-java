package catalog;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Data access for products. Currently an in-memory store seeded at construction. */
public final class CatalogRepository {
    private final Map<String, Product> store = new HashMap<>();

    public CatalogRepository() {
        store.put("sku-1", new Product("sku-1", "Widget", 999));
        store.put("sku-2", new Product("sku-2", "Gadget", 1499));
    }

    /** Look up a product by id. Returns empty if the id is not known. */
    public Optional<Product> find(String id) {
        Product p = store.get(id);
        return Optional.ofNullable(p);
    }
}
