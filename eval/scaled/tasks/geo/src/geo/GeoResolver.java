package geo;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Resolves IPs to locations. Currently a fixed in-memory table seeded at construction. */
public final class GeoResolver {
    private final Map<String, String> known = new HashMap<>();

    public GeoResolver() {
        known.put("10.0.0.1", "DC1");
        known.put("10.0.0.2", "DC2");
    }

    /** Resolve an IP to its location. Returns empty if the IP is not in the local table. */
    public Optional<String> resolve(String ip) {
        return Optional.ofNullable(known.get(ip));
    }
}
