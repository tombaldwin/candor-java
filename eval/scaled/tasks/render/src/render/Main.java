package render;

import java.util.Map;

public final class Main {
    public static void main(String[] args) {
        TemplateEngine engine = new TemplateEngine(Map.of("title", "Home", "footer", "(c)"));
        Page page = new Page(engine);
        RenderController controller = new RenderController(page);
        RenderReport report = new RenderReport(controller);

        System.out.println(controller.renderOne("title"));
        System.out.println(report.buildAll());
    }
}
