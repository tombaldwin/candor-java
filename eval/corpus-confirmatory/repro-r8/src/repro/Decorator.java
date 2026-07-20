package repro;
import java.util.*;
/** Delegates equals to the decorated map — candor should DISCLOSE Unknown (the target is dynamic), not
 *  read it pure. Exactly the AbstractMapDecorator.equals shape from commons-collections4. */
public class Decorator {
    private final Map<String,String> decorated;
    public Decorator(Map<String,String> d) { this.decorated = d; }
    private Map<String,String> decorated() { return decorated; }
    @Override public boolean equals(Object object) {
        if (object == this) return true;
        return decorated().equals(object);   // <- dynamic dispatch; reaches Clock when object is a ClockMap
    }
    @Override public int hashCode() { return decorated().hashCode(); }
}
