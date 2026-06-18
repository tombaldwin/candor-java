package render;

import java.util.List;

/** Renders a page from a list of tokens. */
public final class Page {
    private final TemplateEngine engine;

    public Page(TemplateEngine engine) {
        this.engine = engine;
    }

    public String renderToken(String token) {
        return engine.expand(token);
    }

    public String render(List<String> tokens) {
        StringBuilder sb = new StringBuilder();
        for (String t : tokens) {
            sb.append(renderToken(t));
        }
        return sb.toString();
    }
}
