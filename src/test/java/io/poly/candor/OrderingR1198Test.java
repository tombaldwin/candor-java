package io.poly.candor;

import static io.poly.candor.TestCompiler.rm;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SOUNDNESS R1198 — THE ORDERING RESIDUALS OF R1195: a container in a field of an object held in a field (a field of a
 * field), {@code equals}/{@code hashCode} run through a callee's field twin, a callee's NON-exact inserts into a
 * container its caller handed it, and a comparator handed to a parameter by a caller outside the scan.
 *
 * <p>Every positive was EXECUTED on JDK 21 (fixture {@code javaagent-v068/fx}: package {@code vx}, driven for the
 * comparator parameters by {@code vd.D}, which is not scanned): each wrote its file through {@code Eff.compareTo},
 * {@code EqEff.equals} or {@code EqEff.hashCode}. Every {@code k*} wrote nothing. On main {@code 1fc9ce4} the
 * positives here were absent under {@code deny Fs Unknown <fn>} (the {@code ff01/03/04/05/08} cases were charged
 * there only through an instance field's GLOBAL twin, which also charged {@code kf01/02/03/07} — a smear these
 * controls pin). R1195's own controls (k07, k14-k20) are carried unchanged.
 */
class OrderingR1198Test {

    static final String SINK = "package app;\nfinal class Sink { static void w() { try { java.nio.file.Files"
            + ".writeString(java.nio.file.Path.of(\"/nonexistent-r1198/x\"), \"x\"); } catch (Exception e) {} } }\n";

    static final String TYPES = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "final class Eff implements Comparable<Eff> { final int v; Eff(int v) { this.v = v; }\n"
            + "  public int compareTo(Eff o) { Sink.w(); return Integer.compare(v, o.v); } }\n"
            + "final class Pure implements Comparable<Pure> { final int v; Pure(int v) { this.v = v; }\n"
            + "  public int compareTo(Pure o) { return Integer.compare(v, o.v); } }\n"
            + "final class EqEff { final int v; EqEff(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { Sink.w(); return o instanceof EqEff e && e.v == v; }\n"
            + "  @Override public int hashCode() { Sink.w(); return v; } }\n"
            + "final class EqPure { final int v; EqPure(int v) { this.v = v; }\n"
            + "  @Override public boolean equals(Object o) { return o instanceof EqPure e && e.v == v; }\n"
            + "  @Override public int hashCode() { return v; } }\n"
            + "/** R1195's own classes (its controls k07, k14-k20 are carried here unchanged) */\n"
            + "class Bag { final List<Object> items = new ArrayList<>(); void put(Object o) { items.add(o); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) void order() { Collections.sort((List) items); } int size() { return items.size(); }\n"
            + "  int hash() { return items.hashCode(); }\n"
            + "  boolean same(Bag o) { return items.equals(o.items); }\n"
            + "  boolean within(Collection<?> c) { return c.containsAll(items); }\n"
            + "  int uniq() { return new HashSet<>(items).size(); } }\n"
            + "final class Counter<E> { final Map<E, Integer> m = new HashMap<>(); void inc(E e) { m.put(e, 1); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) List<E> sortedKeys() { List<E> l = new ArrayList<>(m.keySet()); Collections.sort((List) l); return l; }\n"
            + "  int size() { return m.size(); }\n"
            + "  static <E> Counter<E> make() { return new Counter<>(); } }\n"
            + "final class Owner { final Bag bag = new Bag(); }\n"
            + "final class Owner2 { final Bag bag = new Bag(); }\n"
            + "final class Util { static void addEff(List<Object> l) { l.add(new Eff(1)); l.add(new Eff(2)); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) static void sortIt(List<Object> l) { Collections.sort((List) l); }\n"
            + "  static void sortBag(Bag b) { b.order(); }\n"
            + "  static void fillBag(Bag b) { b.put(new Eff(1)); b.put(new Eff(2)); }\n"
            + "  static void fillBagEq(Bag b) { b.put(new EqEff(1)); }\n"
            + "  @SuppressWarnings(\"rawtypes\") static void addDecl(List<Comparable> l) { }\n"
            + "  // ---- R1198 N: NON-EXACT inserts by a callee\n"
            + "  static void addMade(List<Object> l) { l.add(Mk.eff(1)); }\n"
            + "  static void addStatic(List<Object> l) { l.add(Mk.E1); l.add(Mk.E2); }\n"
            + "  static void addCast(List<Object> l, Map<String, Object> m) { l.add((Eff) m.get(\"a\")); l.add((Eff) m.get(\"b\")); }\n"
            + "  static void addPure(List<Object> l) { l.add(Mk.pure(1)); l.add(Mk.pure(2)); }\n"
            + "  @SuppressWarnings(\"rawtypes\") static void addAny(List<Object> l) { l.add(Mk.any(1)); l.add(Mk.any(2)); }\n"
            + "  static void fillMade(Bag b) { b.put(Mk.eff(1)); b.put(Mk.eff(2)); }\n"
            + "  @SuppressWarnings(\"rawtypes\") static void insParam(List<Comparable> l, Comparable x) { l.add(x); }\n"
            + "  static void addEq(List<Object> l) { l.add(Mk.eq(1)); }\n"
            + "  static void addMadeTwice(List<Object> l) { addMade(l); addMade(l); } }\n"
            + "final class Mk { static final Eff E1 = new Eff(1), E2 = new Eff(2);\n"
            + "  static Eff eff(int v) { return new Eff(v); } static Pure pure(int v) { return new Pure(v); }\n"
            + "  @SuppressWarnings(\"rawtypes\") static Comparable any(int v) { return new Eff(v); }\n"
            + "  static EqEff eq(int v) { return new EqEff(v); } }\n"
            + "final class Src { final Eff e; Src(int v) { e = new Eff(v); } void into(List<Object> l) { l.add(e); } }\n"
            + "// ---- R1198 F: a FIELD OF A FIELD\n"
            + "final class Outer { final Bag bag = new Bag(); void add(Object o) { bag.put(o); } void sort() { bag.order(); } int size() { return bag.size(); }\n"
            + "  int hash() { return bag.hash(); } Bag bagOf() { return bag; } }\n"
            + "final class Inner { final List<Object> items = new ArrayList<>(); }\n"
            + "final class Outer2 { final Inner in = new Inner(); void add(Object o) { in.items.add(o); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) void sort() { Collections.sort((List) in.items); } }\n"
            + "final class Top { final Outer out = new Outer(); void add(Object o) { out.add(o); } void sort() { out.sort(); } }\n"
            + "final class Doc { final Counter<Object> c = Counter.make(); void see(Object e) { c.inc(e); } List<Object> top() { return c.sortedKeys(); } int n() { return c.size(); } }\n"
            + "final class Outer3 { final Bag bag; Outer3(Bag b) { bag = b; } void sort() { bag.order(); } int size() { return bag.size(); } }\n"
            + "final class Outer5 { final List<Object> items; Outer5(List<Object> l) { items = new ArrayList<>(l); } void put(Object o) { items.add(o); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) void sort() { Collections.sort((List) items); } }\n"
            + "final class Outer6 { final List<Object> items; Outer6(List<Object> l) { items = l; } int size() { return items.size(); }\n"
            + "  @SuppressWarnings({\"unchecked\", \"rawtypes\"}) void sort() { Collections.sort((List) items); } }\n";

    /** No name is a prefix of another (§3.3). */
    static final String MAIN = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "@SuppressWarnings({\"unchecked\", \"rawtypes\"})\n"
            + "public class N {\n"
            + "  // ---- F: a field of a field\n"
            + "  public static void ff01Outer() { Outer o = new Outer(); o.add(new Eff(2)); o.add(new Eff(1)); o.sort(); }\n"
            + "  public static void ff02Inner() { Outer2 o = new Outer2(); o.add(new Eff(2)); o.add(new Eff(1)); o.sort(); }\n"
            + "  public static void ff03Direct() { Outer o = new Outer(); o.bag.put(new Eff(2)); o.bag.put(new Eff(1)); o.bag.order(); }\n"
            + "  public static void ff04Mixed() { Outer o = new Outer(); o.bag.put(new Eff(2)); o.bag.put(new Eff(1)); o.sort(); }\n"
            + "  public static void ff05Top() { Top t = new Top(); t.add(new Eff(2)); t.add(new Eff(1)); t.sort(); }\n"
            + "  public static void ff06Doc() { Doc d = new Doc(); d.see(new Eff(2)); d.see(new Eff(1)); d.top(); }\n"
            + "  public static void ff07OuterHash() { Outer o = new Outer(); o.add(new EqEff(2)); o.hash(); }\n"
            + "  public static void ff08Static() { Holder.O.add(new Eff(2)); Holder.O.add(new Eff(1)); Holder.O.sort(); }\n"
            + "  // ---- E: equals/hashCode through a callee's field twin\n"
            + "  public static void eh01Hash() { Bag b = new Bag(); b.put(new EqEff(1)); b.hash(); }\n"
            + "  public static void eh02Same() { Bag a = new Bag(); a.put(new EqEff(1)); Bag b = new Bag(); b.put(new EqEff(1)); a.same(b); }\n"
            + "  public static void eh03Within() { Bag a = new Bag(); a.put(new EqEff(1)); List<Object> l = new ArrayList<>(); l.add(new EqPure(1)); a.within(l); }\n"
            + "  public static void eh04Uniq() { Bag a = new Bag(); a.put(new EqEff(1)); a.uniq(); }\n"
            + "  public static void eh05FillHash() { Bag b = new Bag(); Util.fillBagEq(b); b.hash(); }\n"
            + "  // ---- N: a callee's non-exact inserts\n"
            + "  public static void ni01Made() { List<Object> a = new ArrayList<>(); Util.addMade(a); Util.addMade(a); Collections.sort((List) a); }\n"
            + "  public static void ni02Static() { List<Object> a = new ArrayList<>(); Util.addStatic(a); Collections.sort((List) a); }\n"
            + "  public static void ni03Cast() { Map<String, Object> m = new HashMap<>(); m.put(\"a\", new Eff(1)); m.put(\"b\", new Eff(2)); List<Object> a = new ArrayList<>(); Util.addCast(a, m); Collections.sort((List) a); }\n"
            + "  public static void ni04Src() { List<Object> a = new ArrayList<>(); new Src(1).into(a); new Src(2).into(a); Collections.sort((List) a); }\n"
            + "  public static void ni05Any() { List<Object> a = new ArrayList<>(); Util.addAny(a); Collections.sort((List) a); }\n"
            + "  public static void ni06FillMade() { Bag b = new Bag(); Util.fillMade(b); b.order(); }\n"
            + "  public static void ni07Twice() { List<Object> a = new ArrayList<>(); Util.addMadeTwice(a); Collections.sort((List) a); }\n"
            + "  public static void ni08EqHash() { List<Object> a = new ArrayList<>(); Util.addEq(a); a.hashCode(); }\n"
            + "  public static void ni09TreeSet() { List<Object> a = new ArrayList<>(); Util.addMade(a); Util.addMade(a); new TreeSet<>(a); }\n"
            + "  public static void ff09Getter() { Outer o = new Outer(); o.bagOf().put(new Eff(2)); o.bagOf().put(new Eff(1)); o.bagOf().order(); }\n"
            + "  public static void ff10Ctor() { Bag b = new Bag(); b.put(new Eff(2)); b.put(new Eff(1)); Outer3 o = new Outer3(b); o.sort(); }\n"
            + "  public static void ff11GetSort() { Outer o = new Outer(); o.add(new Eff(2)); o.add(new Eff(1)); o.bagOf().order(); }\n"
            + "  public static void cs01CapNat() { Comparator<Eff> c = Comparator.naturalOrder(); List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); l.stream().collect(java.util.stream.Collectors.toCollection(() -> new TreeSet<>(c))); }\n"
            + "  public static void kf07DirectTwo() { Outer a = new Outer(); a.bag.put(new Eff(1)); a.bag.put(new Eff(2)); Outer b = new Outer(); b.bag.put(new Pure(1)); b.bag.put(new Pure(2)); b.bag.order(); }\n"
            + "  public static void kf08GetTwo() { Outer a = new Outer(); a.add(new Eff(1)); a.add(new Eff(2)); Outer b = new Outer(); b.add(new Pure(1)); b.add(new Pure(2)); b.bagOf().order(); }\n"
            + "  public static void kc06CapCmpInt() { Comparator<Eff> c = Comparator.comparingInt(x -> x.v); List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); l.stream().collect(java.util.stream.Collectors.toCollection(() -> new TreeSet<>(c))); }\n"
            + "  public static void ni10Fwd() { List<Object> a = new ArrayList<>(); a.add(Mk.any(1)); a.add(Mk.any(2)); Collections.sort((List) a); }\n"
            + "  public static void ff12CopyBack() { List<Object> l = new ArrayList<>(); Outer5 o = new Outer5(l); o.put(new Eff(1)); o.put(new Eff(2)); o.sort(); }\n"
            + "  public static void ff13Shared() { List<Object> l = new ArrayList<>(); Outer6 o = new Outer6(l); l.add(new Eff(1)); l.add(new Eff(2)); o.sort(); }\n"
            + "  public static void kf09CtorTwo() { Bag a = new Bag(); a.put(new Eff(1)); a.put(new Eff(2)); new Outer3(a).size(); Bag b = new Bag(); b.put(new Pure(1)); b.put(new Pure(2)); new Outer3(b).sort(); }\n"
            + "  public static void kf10CopyCtor() { List<Object> l = new ArrayList<>(); l.add(new Pure(1)); l.add(new Pure(2)); Outer5 o = new Outer5(l); o.put(new Eff(1)); Util.sortIt(l); }\n"
            + "  public static void kf11GetTwo() { Outer a = new Outer(); a.bagOf().put(new Eff(1)); a.bagOf().put(new Eff(2)); Outer b = new Outer(); b.bagOf().put(new Pure(1)); b.bagOf().put(new Pure(2)); b.bagOf().order(); }\n"
            + "  public static void kf12SharedTwo() { List<Object> l = new ArrayList<>(); l.add(new Eff(1)); l.add(new Eff(2)); List<Object> m = new ArrayList<>(); m.add(new Pure(1)); m.add(new Pure(2)); new Outer6(l).size(); new Outer6(m).sort(); }\n"
            + "  // ---- controls (real = 0 for Fs)\n"
            + "  public static void k07BagTwo() { Bag a = new Bag(); a.put(new Eff(1)); a.put(new Eff(2)); a.size(); Bag b = new Bag(); b.put(new Pure(1)); b.put(new Pure(2)); b.order(); }\n"
            + "  public static void k14CounterTwo() { Counter<Eff> a = new Counter<>(); a.inc(new Eff(1)); a.inc(new Eff(2)); a.size(); Counter<Pure> b = new Counter<>(); b.inc(new Pure(1)); b.inc(new Pure(2)); b.sortedKeys(); }\n"
            + "  public static void k15CounterMake() { Counter<Eff> a = Counter.make(); a.inc(new Eff(1)); a.inc(new Eff(2)); a.size(); Counter<Pure> b = Counter.make(); b.inc(new Pure(1)); b.inc(new Pure(2)); b.sortedKeys(); }\n"
            + "  public static void k16PureSortOnly() { Counter<Pure> b = Counter.make(); b.inc(new Pure(1)); b.inc(new Pure(2)); b.sortedKeys(); }\n"
            + "  public static void k17BackOther() { List<Object> a = new ArrayList<>(); Util.addEff(a); a.size(); List<Object> b = new ArrayList<>(); b.add(new Pure(1)); b.add(new Pure(2)); Util.sortIt(b); }\n"
            + "  public static void k18SortBagPure() { Bag e = new Bag(); Util.fillBag(e); e.size(); Bag p = new Bag(); p.put(new Pure(1)); p.put(new Pure(2)); Util.sortBag(p); }\n"
            + "  public static void k19Owners() { Owner a = new Owner(); a.bag.put(new Eff(1)); a.bag.put(new Eff(2)); Owner2 b = new Owner2(); b.bag.put(new Pure(1)); b.bag.put(new Pure(2)); b.bag.order(); }\n"
            + "  public static void k20Decl() { List<Comparable> l = new ArrayList<>(); Util.addDecl(l); l.add(new Pure(1)); l.add(new Pure(2)); Collections.sort(l); }\n"
            + "  public static void kf01OuterTwo() { Outer a = new Outer(); a.add(new Eff(1)); a.add(new Eff(2)); a.size(); Outer b = new Outer(); b.add(new Pure(1)); b.add(new Pure(2)); b.sort(); }\n"
            + "  public static void kf02OuterPure() { Outer b = new Outer(); b.add(new Pure(1)); b.add(new Pure(2)); b.sort(); }\n"
            + "  public static void kf03TopTwo() { Top a = new Top(); a.add(new Eff(1)); a.add(new Eff(2)); Top b = new Top(); b.add(new Pure(1)); b.add(new Pure(2)); b.sort(); }\n"
            + "  public static void kf04DocTwo() { Doc a = new Doc(); a.see(new Eff(1)); a.see(new Eff(2)); a.n(); Doc b = new Doc(); b.see(new Pure(1)); b.see(new Pure(2)); b.top(); }\n"
            + "  public static void kf05OuterNoSort() { Outer a = new Outer(); a.add(new Eff(1)); a.add(new Eff(2)); a.size(); }\n"
            + "  public static void kf06Inner2() { Outer2 a = new Outer2(); a.add(new Eff(1)); Outer2 b = new Outer2(); b.add(new Pure(1)); b.add(new Pure(2)); b.sort(); }\n"
            + "  public static void kh01HashPure() { Bag b = new Bag(); b.put(new EqPure(1)); b.hash(); }\n"
            + "  public static void kh02HashTwo() { Bag a = new Bag(); a.put(new EqEff(1)); a.size(); Bag b = new Bag(); b.put(new EqPure(1)); b.hash(); }\n"
            + "  public static void kh03HashNone() { Bag a = new Bag(); a.put(new EqEff(1)); a.size(); }\n"
            + "  public static void kn01MadePure() { List<Object> a = new ArrayList<>(); Util.addPure(a); Collections.sort((List) a); }\n"
            + "  public static void kn02MadeOther() { List<Object> a = new ArrayList<>(); Util.addMade(a); a.size(); List<Object> b = new ArrayList<>(); Util.addPure(b); Collections.sort((List) b); }\n"
            + "  public static void kn03InsParam() { List<Comparable> l = new ArrayList<>(); Util.insParam(l, new Pure(1)); Util.insParam(l, new Pure(2)); Collections.sort(l); }\n"
            + "  public static void kn04FillMadeNo() { Bag b = new Bag(); Util.fillMade(b); b.size(); Bag p = new Bag(); p.put(new Pure(1)); p.put(new Pure(2)); p.order(); }\n"
            + "  public static void kn05EqNoHash() { List<Object> a = new ArrayList<>(); Util.addEq(a); a.size(); }\n"
            + "}\n"
            + "final class Holder { static final Outer O = new Outer(); }\n";

    /** The comparator parameters: their caller is OUTSIDE the scan. */
    static final String API = ""
            + "package app;\n"
            + "import java.util.*;\n"
            + "import java.util.stream.*;\n"
            + "/** R1198 C: a comparator handed to a PARAMETER by a caller OUTSIDE the scan (vd.D, not scanned) */\n"
            + "public final class Api {\n"
            + "  public static void cp01Sort(List<Eff> l, Comparator<? super Eff> c) { l.sort(c); }\n"
            + "  public static void cp02Coll(List<Eff> l, Comparator<? super Eff> c) { Collections.sort(l, c); }\n"
            + "  public static void cp03Stream(List<Eff> l, Comparator<? super Eff> c) { l.stream().sorted(c).collect(Collectors.toList()); }\n"
            + "  public static void cp04Max(List<Eff> l, Comparator<? super Eff> c) { Collections.max(l, c); }\n"
            + "  public static void cp05Tree(List<Eff> l, Comparator<? super Eff> c) { new TreeSet<Eff>(c).addAll(l); }\n"
            + "  public static void cp06Pq(Comparator<? super Eff> c) { PriorityQueue<Eff> q = new PriorityQueue<>(c); q.add(new Eff(2)); q.add(new Eff(1)); }\n"
            + "  public static void cp07Rev(List<Eff> l, Comparator<Eff> c) { l.sort(c.reversed()); }\n"
            + "  public static void cp08Arr(Object[] a, Comparator<Object> c) { Arrays.sort(a, c); }\n"
            + "  public static void cp09Thn(List<Eff> l, Comparator<Eff> c) { l.sort(c.thenComparing(Comparator.naturalOrder())); }\n"
            + "  public static void cp10Min(List<Eff> l, Comparator<? super Eff> c) { l.stream().min(c); }\n"
            + "  public static void cp11TreeAdd(Comparator<? super Eff> c) { TreeSet<Eff> t = new TreeSet<>(c); t.add(new Eff(2)); t.add(new Eff(1)); }\n"
            + "  public static void cp12Map(Comparator<? super Eff> c) { TreeMap<Eff, String> t = new TreeMap<>(c); t.put(new Eff(2), \"a\"); t.put(new Eff(1), \"b\"); }\n"
            + "  public static void cp13Own(List<Eff> l, Comparator<? super Eff> c) { helper(l, c); }\n"
            + "  static void helper(List<Eff> l, Comparator<? super Eff> c) { l.sort(c); }\n"
            + "  public static void cp14Obj(List<Object> l, Comparator<Object> c) { l.sort(c); }\n"
            + "  public static void cp15Ctor(List<Eff> l, Comparator<? super Eff> c) { new Sorter(c).sort(l); }\n"
            + "  public static void cp16Setter(List<Eff> l, Comparator<? super Eff> c) { Sorter s = new Sorter(null); s.set(c); s.sort(l); }\n"
            + "  public static void cp17FieldPq(Comparator<? super Eff> c) { new Sorter(c).pq(); }\n"
            + "  public static void cp18HelpTree(List<Eff> l, Comparator<? super Eff> c) { tree(l, c); }\n"
            + "  static void tree(List<Eff> l, Comparator<? super Eff> c) { TreeSet<Eff> t = new TreeSet<>(c); t.addAll(l); }\n"
            + "  public static void cp19RevOf(List<Eff> l, Comparator<Eff> c) { l.sort(Collections.reverseOrder(c)); }\n"
            + "  public static void cp20Nulls(List<Eff> l, Comparator<Eff> c) { l.sort(Comparator.nullsFirst(c)); }\n"
            + "  public static void cp21Pq2(Comparator<? super Eff> c) { PriorityQueue<Eff> q = new PriorityQueue<>(11, c); q.add(new Eff(2)); q.add(new Eff(1)); }\n"
            + "  public static void cp22PutAll(Map<Eff, String> m, Comparator<? super Eff> c) { new TreeMap<Eff, String>(c).putAll(m); }\n"
            + "  public static void cp23Skip(Comparator<? super Eff> c) { java.util.concurrent.ConcurrentSkipListSet<Eff> s = new java.util.concurrent.ConcurrentSkipListSet<>(c); s.add(new Eff(2)); s.add(new Eff(1)); }\n"
            + "  public static void cp24Bin(List<Eff> l, Comparator<? super Eff> c) { Collections.binarySearch(l, new Eff(1), c); }\n"
            + "  public static void cp25SortRev(List<Eff> l, Comparator<Eff> c) { l.stream().sorted(c.reversed()).collect(Collectors.toList()); }\n"
            + "  public static void cp26Coll(List<Eff> l, Comparator<? super Eff> c) { l.stream().collect(Collectors.toCollection(() -> new TreeSet<Eff>(c))); }\n"
            + "  public static void cp27Key(List<Holder2> l, Comparator<Eff> c) { l.sort(Comparator.comparing(Holder2::key, c)); }\n"
            + "  public static void cp28Local(List<Eff> l, Comparator<? super Eff> c) { Comparator<? super Eff> d = c; l.sort(d); }\n"
            + "  public static void cp29Inst(List<Eff> l, Comparator<? super Eff> c) { new Sorter(null).sortWith(l, c); }\n"
            + "  public static List<Holder2> holds() { List<Holder2> l = new ArrayList<>(); l.add(new Holder2(2)); l.add(new Holder2(1)); return l; }\n"
            + "  public static Map<Eff, String> effMap() { Map<Eff, String> m = new HashMap<>(); m.put(new Eff(2), \"a\"); m.put(new Eff(1), \"b\"); return m; }\n"
            + "  // controls (real = 0): pure elements, or a comparator that never runs\n"
            + "  public static void kc01Pure(List<Pure> l, Comparator<? super Pure> c) { l.sort(c); }\n"
            + "  public static void kc02Unused(List<Eff> l, Comparator<? super Eff> c) { l.size(); }\n"
            + "  public static void kc03One(Comparator<? super Eff> c) { PriorityQueue<Eff> q = new PriorityQueue<>(c); q.add(new Eff(2)); }\n"
            + "  public static void kc04PureQ(Comparator<? super Pure> c) { PriorityQueue<Pure> q = new PriorityQueue<>(c); q.add(new Pure(2)); q.add(new Pure(1)); }\n"
            + "  public static void kc05Store(Comparator<? super Eff> c) { KEEP = c; }\n"
            + "  static Comparator<? super Eff> KEEP;\n"
            + "  public static List<Eff> effs() { List<Eff> l = new ArrayList<>(); l.add(new Eff(2)); l.add(new Eff(1)); return l; }\n"
            + "  public static List<Pure> pures() { List<Pure> l = new ArrayList<>(); l.add(new Pure(2)); l.add(new Pure(1)); return l; }\n"
            + "  public static Object[] effArr() { return effs().toArray(); }\n"
            + "}\n"
            + "final class Sorter { Comparator<? super Eff> c; Sorter(Comparator<? super Eff> c) { this.c = c; } void set(Comparator<? super Eff> c) { this.c = c; }\n"
            + "  void sort(List<Eff> l) { l.sort(c); } void pq() { PriorityQueue<Eff> q = new PriorityQueue<>(c); q.add(new Eff(2)); q.add(new Eff(1)); }\n"
            + "  void sortWith(List<Eff> l, Comparator<? super Eff> d) { l.sort(d); } }\n"
            + "final class Holder2 { final Eff k; Holder2(int v) { k = new Eff(v); } Eff key() { return k; } }\n";

    static final List<String> REAL = List.of("ff01Outer", "ff02Inner", "ff03Direct", "ff04Mixed", "ff05Top", "ff06Doc", "ff07OuterHash", "ff08Static", "eh01Hash", "eh02Same", "eh03Within", "eh04Uniq", "eh05FillHash", "ni01Made", "ni02Static", "ni03Cast", "ni04Src", "ni06FillMade", "ni07Twice", "ni08EqHash", "ni09TreeSet", "ff09Getter", "ff10Ctor", "ff11GetSort", "cs01CapNat", "ff12CopyBack", "ff13Shared");
    static final List<String> CONTROLS = List.of("kf07DirectTwo", "kf08GetTwo", "kc06CapCmpInt", "kf09CtorTwo", "kf10CopyCtor", "kf11GetTwo", "k07BagTwo", "k14CounterTwo", "k15CounterMake", "k16PureSortOnly", "k17BackOther", "k18SortBagPure", "k19Owners", "k20Decl", "kf01OuterTwo", "kf02OuterPure", "kf03TopTwo", "kf04DocTwo", "kf05OuterNoSort", "kf06Inner2", "kh01HashPure", "kh02HashTwo", "kh03HashNone", "kn01MadePure", "kn02MadeOther", "kn03InsParam", "kn04FillMadeNo", "kn05EqNoHash");
    static final List<String> API_REAL = List.of("cp01Sort", "cp02Coll", "cp03Stream", "cp04Max", "cp05Tree", "cp06Pq", "cp07Rev", "cp08Arr", "cp09Thn", "cp10Min", "cp11TreeAdd", "cp12Map", "cp13Own", "cp14Obj", "cp15Ctor", "cp16Setter", "cp17FieldPq", "cp18HelpTree", "cp19RevOf", "cp20Nulls", "cp21Pq2", "cp22PutAll", "cp23Skip", "cp24Bin", "cp25SortRev", "cp26Coll", "cp27Key", "cp28Local", "cp29Inst");

    static Map<String, String> app() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("app/Sink.java", SINK);
        m.put("app/T.java", TYPES);
        m.put("app/N.java", MAIN);
        m.put("app/Api.java", API);
        return m;
    }

    @SuppressWarnings("unchecked")
    static List<String> inferred(Map<String, Map<String, Object>> r, String fn) {
        Map<String, Object> row = r.get(fn);
        return row == null ? List.of() : (List<String>) row.get("inferred");
    }

    // ---- the over-charge controls, written first -------------------------------------------------------

    @Test
    void controlsChargeNothingAndNoTwoInstancesMeet() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : CONTROLS)
                assertTrue(!inferred(r, "app.N." + fn).contains("Fs"), fn + " runs no effectful compareTo/equals/hashCode (executed); got "
                        + r.get("app.N." + fn));
            // the classes' own sorts keep only what their signatures name: their CALLERS are charged
            for (String fn : List.of("app.Bag.order", "app.Outer.sort", "app.Top.sort", "app.Outer2.sort", "app.Bag.hash"))
                assertTrue(!inferred(r, fn).contains("Fs"), fn + " got " + r.get(fn));
            // a comparator parameter over PURE elements, or one never run, charges nothing
            for (String fn : List.of("kc01Pure", "kc02Unused", "kc04PureQ", "kc05Store"))
                assertTrue(!inferred(r, "app.Api." + fn).contains("Fs"), fn + " got " + r.get("app.Api." + fn));
            for (String fn : List.of("kc02Unused", "kc04PureQ", "kc05Store"))
                assertTrue(inferred(r, "app.Api." + fn).isEmpty(), fn + " got " + r.get("app.Api." + fn));
        } finally {
            t.close();
        }
    }

    // ---- the row ----------------------------------------------------------------------------------------

    @Test
    void theFieldOfAFieldEqualsHashCodeAndNonExactInsertsAreCharged() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : REAL)
                assertTrue(inferred(r, "app.N." + fn).contains("Fs"), fn + " runs an effectful compareTo/equals/hashCode (executed); got "
                        + r.get("app.N." + fn));
        } finally {
            t.close();
        }
    }

    @Test
    void aComparatorParameterIsDisclosedWhereItRuns() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            for (String fn : API_REAL) {
                List<String> inf = inferred(r, "app.Api." + fn);
                assertTrue(inf.contains("Fs") || inf.contains("Unknown"), fn + " runs its caller's comparator over Eff (executed); got "
                        + r.get("app.Api." + fn));
            }
        } finally {
            t.close();
        }
    }

    /** STATED RESIDUAL, not closed: an element whose declared type is a JDK interface ({@code Comparable}) names no
     *  body, here or in the forward direction ({@code ni10Fwd}, the same insert made in the sorting body). */
    @Test
    void aJdkInterfaceElementStaysTheStatedResidual() throws Exception {
        Tree t = Tree.of(app());
        try {
            Map<String, Map<String, Object>> r = byFn(t.scanAll());
            assertTrue(inferred(r, "app.N.ni10Fwd").isEmpty() && inferred(r, "app.N.ni05Any").isEmpty(),
                    "if these now charge, close the residual in the row: " + r.get("app.N.ni05Any") + " " + r.get("app.N.ni10Fwd"));
        } finally {
            t.close();
        }
    }

    // ---- harness (OrderingR1179Test's) -------------------------------------------------------------------

    private static final class Tree implements AutoCloseable {
        final Path base;
        private final Config saved = Candor.config;

        private Tree(Path base) { this.base = base; }

        @SafeVarargs
        static Tree of(Map<String, String>... pkgs) throws Exception {
            Map<String, String> all = new LinkedHashMap<>();
            for (Map<String, String> p : pkgs) all.putAll(p);
            Path cls = TestCompiler.compile(all);
            Path base = cls.getParent();
            try (var s = Files.list(cls)) {
                for (Path top : s.toList()) {
                    if (!Files.isDirectory(top)) continue;
                    Path dir = base.resolve("d_" + top.getFileName());
                    Files.createDirectories(dir);
                    copyTree(top, dir.resolve(top.getFileName()));
                    copyTree(top, base.resolve("d_all").resolve(top.getFileName()));
                }
            }
            return new Tree(base);
        }

        String scan(String pkg) throws Exception { return scanChained(pkg); }

        String scanAll() throws Exception {
            Files.deleteIfExists(base.resolve(".candor/config"));
            Candor.config = Config.empty();
            Path out = base.resolve("all.json");
            Files.deleteIfExists(out);
            ReportWriter.writeJson(Candor.runScan(base.resolve("d_all")), out.toString());
            return out.toString();
        }

        String scanChained(String pkg, String... deps) throws Exception {
            Path dir = base.resolve("d_" + pkg);
            Path out = base.resolve(pkg + "-" + Math.abs(String.join(",", deps).hashCode()) + ".json");
            Files.deleteIfExists(out);
            Files.createDirectories(base.resolve(".candor"));
            if (deps.length == 0) {
                Files.deleteIfExists(base.resolve(".candor/config"));
                Candor.config = Config.empty();
            } else {
                Files.writeString(base.resolve(".candor/config"), "deps " + String.join(" ", deps) + "\n");
                Candor.config = Config.forTarget(dir);
            }
            ReportWriter.writeJson(Candor.runScan(dir), out.toString());
            return out.toString();
        }

        @Override
        public void close() {
            Candor.config = saved;
            rm(base);
        }
    }

    private static void copyTree(Path from, Path to) throws Exception {
        Files.createDirectories(to);
        try (var s = Files.list(from)) {
            for (Path p : s.toList()) {
                if (Files.isDirectory(p)) copyTree(p, to.resolve(p.getFileName()));
                else Files.copy(p, to.resolve(p.getFileName()), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> byFn(String reportPath) throws Exception {
        Map<String, Object> doc = new Gson().fromJson(Files.readString(Path.of(reportPath)), Map.class);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Object o : (List<Object>) doc.getOrDefault("functions", new ArrayList<>())) {
            Map<String, Object> e = (Map<String, Object>) o;
            out.put((String) e.get("fn"), e);
        }
        return out;
    }
}
