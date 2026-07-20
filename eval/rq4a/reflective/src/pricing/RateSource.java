package pricing;

/** The FX-rate port the domain depends on. It is an interface declared IN the domain
 *  package — the domain owns the abstraction; the implementation lives elsewhere and is
 *  injected. The domain therefore never names an infrastructure type or a `java.net` type,
 *  which is exactly why a package/import-graph rule sees the domain as I/O-free. */
public interface RateSource {
    /** The current USD->currency rate in milli-units (1000 = parity). */
    long current(String currency);
}
