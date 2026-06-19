package model;

/** A cart line: a SKU and a quantity. */
public final class Line {
    public final String sku;
    public final int qty;

    public Line(String sku, int qty) {
        this.sku = sku;
        this.qty = qty;
    }
}
