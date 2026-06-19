import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * In-process stub JDBC driver — lets the self-test exercise the java.sql Db leaves without a real DB.
 *
 * connect() returns a dynamic-proxy Connection. createStatement() returns a proxy Statement, whose
 * executeQuery() returns a proxy ResultSet. The point is purely that the CALL SITES in
 * AgentSelfTest.stubDb statically reference the java.sql INTERFACES (java/sql/Connection,
 * java/sql/Statement), which is what the agent's leaf table matches — so the Db record() fires there.
 *
 * NOTE: the proxy InvocationHandler runs no SQL; it is not itself an effect. The instrumentation is at
 * the caller's bytecode (the INVOKEINTERFACE), so the observed Db is attributed to stubDb (the caller),
 * not to the stub — exactly the per-method semantics we want.
 */
public final class StubDriver {
    private StubDriver() {}

    static Connection connect() {
        return (Connection) Proxy.newProxyInstance(
                StubDriver.class.getClassLoader(),
                new Class<?>[]{Connection.class},
                new H());
    }

    static final class H implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method m, Object[] a) {
            switch (m.getName()) {
                case "createStatement":
                    return Proxy.newProxyInstance(StubDriver.class.getClassLoader(),
                            new Class<?>[]{Statement.class}, new H());
                case "executeQuery":
                    return Proxy.newProxyInstance(StubDriver.class.getClassLoader(),
                            new Class<?>[]{ResultSet.class}, new H());
                case "next":   return Boolean.FALSE;
                case "close":  return null;
                case "equals": return proxy == a[0];
                case "hashCode": return System.identityHashCode(proxy);
                case "toString": return "stub";
                default:
                    Class<?> r = m.getReturnType();
                    if (r == boolean.class) return Boolean.FALSE;
                    if (r == int.class) return 0;
                    if (r == long.class) return 0L;
                    return null;
            }
        }
    }
}
