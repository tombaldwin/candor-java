package catalog;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Business layer over the repository. */
public final class CatalogService {
    private final CatalogRepository repo;

    public CatalogService(CatalogRepository repo) {
        this.repo = repo;
    }

    /** Resolve one product. */
    public Optional<Product> lookup(String id) {
        return repo.find(id);
    }

    /** Resolve several products, skipping unknown ids. */
    public List<Product> batch(List<String> ids) {
        List<Product> out = new ArrayList<>();
        for (String id : ids) {
            lookup(id).ifPresent(out::add);
        }
        return out;
    }
}
