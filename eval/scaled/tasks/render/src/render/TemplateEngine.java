package render;

import java.util.Map;

/** Expands template tokens to strings using a fixed context map. */
public final class TemplateEngine {
    private final Map<String, String> context;

    public TemplateEngine(Map<String, String> context) {
        this.context = context;
    }

    /** Expand one token to its replacement text. Unknown tokens expand to the empty string. */
    public String expand(String token) {
        return context.getOrDefault(token, "");
    }
}
