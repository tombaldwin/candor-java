package catalog;

public final class Main {
    public static void main(String[] args) {
        CatalogRepository repo = new CatalogRepository();
        CatalogService service = new CatalogService(repo);
        CatalogController controller = new CatalogController(service);
        DashboardReport report = new DashboardReport(controller);

        System.out.println(controller.getOne("sku-1").map(p -> p.name).orElse("?"));
        System.out.println(report.build());
    }
}
