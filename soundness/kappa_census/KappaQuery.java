package io.poly.candor;

import java.io.*;
import java.nio.charset.StandardCharsets;

/** Reads `owner\tmethod\tdesc` lines on stdin, prints `owner\tmethod\tdesc\t<effect-or-NULL>`.
 *  A direct query of the κ NAME TABLE — no scan, no bodies. */
public final class KappaQuery {
    public static void main(String[] a) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintWriter w = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            if (line.isEmpty()) continue;
            String[] p = line.split("\t", -1);
            if (p.length < 3) continue;
            Object e;
            try { e = Classifier.classify(p[0], p[1], p[2]); }
            catch (Throwable t) { e = "ERR:" + t; }
            w.println(p[0] + "\t" + p[1] + "\t" + p[2] + "\t" + (e == null ? "NULL" : e.toString()));
        }
        w.flush();
    }
}
