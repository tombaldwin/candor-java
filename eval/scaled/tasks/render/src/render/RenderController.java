package render;

import java.util.List;

/** Request entry points for rendering. */
public final class RenderController {
    private final Page page;

    public RenderController(Page page) {
        this.page = page;
    }

    public String renderOne(String token) {
        return page.renderToken(token);
    }

    public String renderMany(List<String> tokens) {
        return page.render(tokens);
    }
}
