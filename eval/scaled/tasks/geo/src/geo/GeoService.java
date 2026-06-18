package geo;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Business layer over the resolver. */
public final class GeoService {
    private final GeoResolver resolver;

    public GeoService(GeoResolver resolver) {
        this.resolver = resolver;
    }

    /** Locate a single IP. */
    public Optional<GeoRecord> locate(String ip) {
        return resolver.resolve(ip).map(loc -> new GeoRecord(ip, loc));
    }

    /** Locate several IPs, skipping any that don't resolve. */
    public List<GeoRecord> batch(List<String> ips) {
        List<GeoRecord> out = new ArrayList<>();
        for (String ip : ips) {
            locate(ip).ifPresent(out::add);
        }
        return out;
    }
}
