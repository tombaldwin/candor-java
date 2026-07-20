package infra;

import pricing.RateSource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** Effectful adapter (Net). Loaded REFLECTIVELY by Main (Class.forName), so no `new HttpRateSource()`
 *  allocation exists anywhere in the bytecode — which is what defeats a points-to call graph. */
public final class HttpRateSource implements RateSource {
    @Override
    public long current(String currency) {
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
