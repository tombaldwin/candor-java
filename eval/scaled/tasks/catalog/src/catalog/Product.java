package catalog;

/** A catalog product. */
public final class Product {
    public final String id;
    public final String name;
    public final int priceCents;

    public Product(String id, String name, int priceCents) {
        this.id = id;
        this.name = name;
        this.priceCents = priceCents;
    }
}
