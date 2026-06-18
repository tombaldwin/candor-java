package geo;

public final class Main {
    public static void main(String[] args) {
        GeoResolver resolver = new GeoResolver();
        GeoService service = new GeoService(resolver);
        GeoController controller = new GeoController(service);
        GeoReport report = new GeoReport(controller);

        System.out.println(controller.lookupOne("10.0.0.1").map(r -> r.location).orElse("?"));
        System.out.println(report.summary());
    }
}
