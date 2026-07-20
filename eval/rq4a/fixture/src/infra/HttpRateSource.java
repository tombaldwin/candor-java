package infra;

import pricing.RateSource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** The infrastructure adapter: a concrete {@link RateSource} that fetches the live rate over
 *  TCP from the internal rates server (see the fixture task). THIS is where `java.net` lives —
 *  in the infrastructure layer, where the policy permits it. The domain (`pricing`) reaches this
 *  network effect only transitively, through the {@link RateSource} port it depends on. */
public final class HttpRateSource implements RateSource {
    private final String host;
    private final int port;

    public HttpRateSource(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public long current(String currency) {
        try (Socket sock = new Socket(host, port)) {
            OutputStream out = sock.getOutputStream();
            out.write((currency + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            String line = in.readLine();
            return line == null ? 1000L : Long.parseLong(line.trim());
        } catch (Exception e) {
            return 1000L; // parity on failure — keeps the fixture runnable without the server
        }
    }
}
