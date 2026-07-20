package pricing;

import money.Money;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;                       // ← the domain now NAMES java.net directly
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** The NAIVE version: the live-rate fetch is inlined straight into the domain, so `pricing`
 *  imports `java.net.Socket`. This is the control — here the effect is a DIRECT dependency, and
 *  an import-graph gate CAN see it. It exists to show ArchUnit's rule has teeth: the green verdict
 *  on the ported fixture is caused by the port indirection, not by a toothless rule. */
public final class Pricing {
    private final Map<String, Long> catalogue = Map.of("WIDGET", 2500L, "GADGET", 4200L);

    public Money quote(String sku, String currency) {
        long base = catalogue.getOrDefault(sku, 0L);
        long rateMilli = fetchRate(currency);
        Money usd = new Money(base, "USD");
        Money converted = usd.scale(rateMilli);
        return new Money(converted.amountMilli, currency);
    }

    private long fetchRate(String currency) {
        try (Socket sock = new Socket("rates.internal", 7070)) {
            OutputStream out = sock.getOutputStream();
            out.write((currency + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            String line = in.readLine();
            return line == null ? 1000L : Long.parseLong(line.trim());
        } catch (Exception e) {
            return 1000L;
        }
    }
}
