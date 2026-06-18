package geo;

import java.util.List;
import java.util.Optional;

/** Request entry points for geo lookups. */
public final class GeoController {
    private final GeoService service;

    public GeoController(GeoService service) {
        this.service = service;
    }

    public Optional<GeoRecord> lookupOne(String ip) {
        return service.locate(ip);
    }

    public List<GeoRecord> lookupMany(List<String> ips) {
        return service.batch(ips);
    }
}
