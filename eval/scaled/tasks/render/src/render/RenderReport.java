package render;

import java.util.List;

/** Builds the full page for the standard token set. */
public final class RenderReport {
    private final RenderController controller;

    public RenderReport(RenderController controller) {
        this.controller = controller;
    }

    public String buildAll() {
        return controller.renderMany(List.of("title", "exec:hostname", "footer"));
    }
}
