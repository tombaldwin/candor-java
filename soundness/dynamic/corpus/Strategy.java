package corpus;

import java.util.UUID;

/**
 * Corpus entry (agent_diff: Exec + Clock + Rand) — three effects reached through a STRATEGY interface.
 * Each effect leaf lives in a concrete strategy object selected at runtime and invoked through the
 * interface type, so candor must resolve the interface dispatch to each concrete body to predict them.
 *
 *   Exec  : run -> ExecStrategy.act  -> ProcessBuilder("echo", ...).start()
 *   Clock : run -> ClockStrategy.act -> System.currentTimeMillis()
 *   Rand  : run -> RandStrategy.act  -> UUID.randomUUID()  (entropy draw)
 *
 * All effects are real and observable by the agent's leaf table; no external network/DB (exec uses echo).
 */
public class Strategy {

    interface Op { void act() throws Exception; }

    static final class ExecStrategy implements Op {
        public void act() throws Exception {
            Process p = new ProcessBuilder("echo", "strategy-exec").start();
            p.getInputStream().readAllBytes();
            p.waitFor();
        }
    }

    static final class ClockStrategy implements Op {
        public void act() {
            long t = System.currentTimeMillis();   // Clock leaf
            if (t < 0) throw new IllegalStateException();
        }
    }

    static final class RandStrategy implements Op {
        public void act() {
            UUID u = UUID.randomUUID();             // Rand leaf
            if (u == null) throw new IllegalStateException();
        }
    }

    /** Runs the op through the interface type — dispatch candor must resolve to each concrete body. */
    static void run(Op op) throws Exception { op.act(); }

    public static void main(String[] args) throws Exception {
        for (Op op : new Op[] { new ExecStrategy(), new ClockStrategy(), new RandStrategy() }) {
            run(op);
        }
        System.out.println("Strategy: ran Exec + Clock + Rand via Op interface dispatch");
    }
}
