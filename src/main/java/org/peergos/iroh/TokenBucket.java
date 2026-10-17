package org.peergos.iroh;

/** A token bucket that may go into debt: a consumer takes what it needs and waits until the debt is refilled. */
final class TokenBucket {

    private final double ratePerNano;
    private final double max;
    private double tokens;
    private long last;

    TokenBucket(double perSecond, double max) {
        if (perSecond <= 0 || max <= 0) {
            throw new IllegalArgumentException("rate and burst must be positive");
        }
        this.ratePerNano = perSecond / 1e9;
        this.max = max;
        this.tokens = max;
        this.last = System.nanoTime();
    }

    /** Takes the tokens, and returns how many nanoseconds to wait before the bucket is out of debt (0 if not in debt). */
    synchronized long consume(double amount) {
        long now = System.nanoTime();
        tokens = Math.min(max, tokens + (now - last) * ratePerNano);
        last = now;
        tokens -= amount;
        return tokens >= 0? 0: (long) Math.ceil(-tokens / ratePerNano);
    }
}
