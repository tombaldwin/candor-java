package io.poly.candor;

import io.poly.candor.model.Effect;

import java.io.*;
import java.nio.charset.StandardCharsets;

/** Reads `owner\tmethod\tdesc` lines on stdin, prints `owner\tmethod\tdesc\t&lt;effect-or-NULL&gt;`.
 *  A direct query of the κ NAME TABLE — no scan, no bodies.
 *
 *  <p>The effect is printed as its SPEC NAME ("Env", "Exec") — what a report carries — NOT the enum
 *  constant ("ENV", "EXEC"). SOUNDNESS R496: {@code weaker_claim_census.py} computes
 *  {@code body_effects - {kappa_answer}} to find what κ failed to name, and against "ENV" that
 *  subtraction never removed anything — so EVERY classified member with any concrete reach was reported
 *  as a hit, each one listing κ's own answer among the "missing" effects. Asking the authority for the
 *  name ({@link Effect#specName()}) is the fix; spelling a second copy of the table in the reader is
 *  what the family's "ask the authority" rule exists to prevent. {@code census.py} tests only for the
 *  literal "NULL", so it is unaffected. */
public final class KappaQuery {
    public static void main(String[] a) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintWriter w = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            if (line.isEmpty()) continue;
            String[] p = line.split("\t", -1);
            if (p.length < 3) continue;
            String out;
            try {
                Effect e = Classifier.classify(p[0], p[1], p[2]);
                out = e == null ? "NULL" : e.specName();
            } catch (Throwable t) { out = "ERR:" + t; }
            w.println(p[0] + "\t" + p[1] + "\t" + p[2] + "\t" + out);
        }
        w.flush();
    }
}
