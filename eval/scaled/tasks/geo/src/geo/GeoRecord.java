package geo;

/** A resolved geo location for an IP. */
public final class GeoRecord {
    public final String ip;
    public final String location;

    public GeoRecord(String ip, String location) {
        this.ip = ip;
        this.location = location;
    }
}
