package io.poly.candor.model;

/**
 * The {@code candor} report header (candor-spec §2.1): which engine produced a report and which
 * contract it conforms to. {@code version} is the engine build id (git hash / release), {@code spec}
 * is the candor-spec contract version, {@code toolchain} the language/runtime channel.
 */
public record Provenance(String version, String toolchain, String spec) {}
