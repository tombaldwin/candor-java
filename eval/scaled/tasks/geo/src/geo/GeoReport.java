package geo;

import java.util.List;

/** Builds the location summary for a set of active IPs. */
public final class GeoReport {
    private final GeoController controller;

    public GeoReport(GeoController controller) {
        this.controller = controller;
    }

    public String summary() {
        List<GeoRecord> records = controller.lookupMany(List.of("10.0.0.1", "10.0.0.2", "10.0.0.9"));
        StringBuilder sb = new StringBuilder();
        for (GeoRecord r : records) {
            sb.append(r.ip).append('=').append(r.location).append(' ');
        }
        return sb.toString().trim();
    }
}
