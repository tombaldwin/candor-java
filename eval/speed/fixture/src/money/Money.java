package money;

/** A monetary amount in cents, with simple arithmetic. */
public final class Money {
    public final long amountCents;
    public final String currency;

    public Money(long amountCents, String currency) {
        this.amountCents = amountCents;
        this.currency = currency;
    }

    public Money plus(Money o) {
        return new Money(amountCents + o.amountCents, currency);
    }

    public Money times(long n) {
        return new Money(amountCents * n, currency);
    }
}
