package io.poly.candor.model;

/**
 * A single diagnostic emitted by a gate mode (candor-spec §6): a {@link DiagnosticCode} plus the
 * rendered, code-specific message body. {@link #render()} reproduces the on-the-wire line
 * {@code "[AS-EFF-00x] <message>"} exactly — the message body is whatever the emitting check
 * formatted (the codes carry no single template because, e.g., AS-EFF-008 has two forms).
 */
public record Diagnostic(DiagnosticCode code, String message) {

    /** The full diagnostic line: {@code "[AS-EFF-00x] <message>"}. */
    public String render() {
        return code.bracket() + " " + message;
    }

    @Override
    public String toString() {
        return render();
    }
}
