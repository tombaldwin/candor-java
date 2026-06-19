import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.Statement;

/**
 * End-to-end self-test for the candor leaf-instrumenting agent.
 *
 * Three methods exercise the agent's runtime Exec/Db capture + per-method stack attribution:
 *   directExec()     — calls ProcessBuilder.start() directly. candor SEES this statically (Exec), so the
 *                      agent_diff must be CLEAN for this method (observed Exec == static Exec).
 *   reflectiveExec() — runs the SAME ProcessBuilder.start() via java.lang.reflect.Method.invoke. The
 *                      INVOKESTATIC->reflective call hides the leaf from a direct static call edge; the
 *                      agent still observes the REAL Exec through this method's frame at runtime. Whether
 *                      candor reports Exec / Unknown / pure here is the model-gap signal.
 *   stubDb()         — calls Connection.createStatement()/Statement.executeQuery() through the java.sql
 *                      INTERFACES, backed by an in-process stub driver (no real DB). Proves the agent's
 *                      interface-owner Db leaf matching fires at runtime.
 */
public class AgentSelfTest {

    static void directExec() throws Exception {
        Process p = new ProcessBuilder("echo", "direct-exec-hi").start();
        p.getInputStream().readAllBytes();
        p.waitFor();
    }

    static void reflectiveExec() throws Exception {
        ProcessBuilder pb = new ProcessBuilder("echo", "reflective-exec-hi");
        Method start = ProcessBuilder.class.getMethod("start");
        Process p = (Process) start.invoke(pb);     // the real exec leaf, reached reflectively
        p.getInputStream().readAllBytes();
        p.waitFor();
    }

    static void stubDb() throws Exception {
        Connection c = StubDriver.connect();        // returns a stub Connection (java.sql.Connection)
        Statement s = c.createStatement();          // java/sql/Connection.createStatement -> Db leaf
        s.executeQuery("SELECT 1");                 // java/sql/Statement.executeQuery     -> Db leaf
        s.close();
        c.close();
    }

    public static void main(String[] args) throws Exception {
        directExec();
        reflectiveExec();
        stubDb();
        System.out.println("AgentSelfTest: ran directExec, reflectiveExec, stubDb");
    }
}
