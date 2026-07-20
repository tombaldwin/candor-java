package infra;

import pricing.RateSource;

/** A second implementor, PURE (parity). Its existence means a class-hierarchy over-approximation of
 *  the RateSource call is imprecise (it would union this with the effectful impl). */
public final class PureRateSource implements RateSource {
    @Override
    public long current(String currency) {
        return 1000L;
    }
}
