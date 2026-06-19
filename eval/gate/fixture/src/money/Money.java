package money;

/** A monetary amount in milli-units of a currency, with scaling arithmetic. */
public final class Money {
    public final long amountMilli;
    public final String currency;

    public Money(long amountMilli, String currency) {
        this.amountMilli = amountMilli;
        this.currency = currency;
    }

    /** Scale this amount by a rate expressed in milli-units (1000 = parity). */
    public Money scale(long rateMilli) {
        return new Money(amountMilli * rateMilli / 1000, currency);
    }
}
