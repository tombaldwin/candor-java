package catalog;

import java.util.List;
import java.util.Optional;

/** Request entry points for the catalog. */
public final class CatalogController {
    private final CatalogService service;

    public CatalogController(CatalogService service) {
        this.service = service;
    }

    public Optional<Product> getOne(String id) {
        return service.lookup(id);
    }

    public List<Product> getMany(List<String> ids) {
        return service.batch(ids);
    }
}
