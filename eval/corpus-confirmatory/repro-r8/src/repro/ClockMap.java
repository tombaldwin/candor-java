package repro;
import java.util.AbstractMap; import java.util.*;
/** A Map whose equals/get read the wall clock — the PassiveExpiringMap shape (expiry-on-access). */
public class ClockMap extends AbstractMap<String,String> {
    private final Map<String,String> m = new HashMap<>();
    private void expire() { long now = System.currentTimeMillis(); if (now < 0) m.clear(); } // Clock on access
    @Override public String get(Object k) { expire(); return m.get(k); }
    @Override public Set<Entry<String,String>> entrySet() { expire(); return m.entrySet(); }
}
