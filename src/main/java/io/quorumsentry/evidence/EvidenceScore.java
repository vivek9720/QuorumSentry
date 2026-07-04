package io.quorumsentry.evidence;

public final class EvidenceScore {
    private int score;
    private int confidence;
    private int observations;
    private long firstSeen = Long.MAX_VALUE;
    private long lastSeen = Long.MIN_VALUE;

    public void observe(long timestamp, int weight, int confidenceDelta) {
        observations++;
        score += Math.max(0, weight);
        confidence = Math.min(100, Math.max(0, confidence + confidenceDelta));
        firstSeen = Math.min(firstSeen, timestamp);
        lastSeen = Math.max(lastSeen, timestamp);
    }

    public void merge(EvidenceScore other) {
        if (other == null) return;
        score += other.score;
        confidence = Math.min(100, confidence + other.confidence / 2);
        observations += other.observations;
        firstSeen = Math.min(firstSeen, other.firstSeen);
        lastSeen = Math.max(lastSeen, other.lastSeen);
    }

    public int score() { return score; }
    public int confidence() { return confidence; }
    public int observations() { return observations; }
    public long firstSeen() { return firstSeen == Long.MAX_VALUE ? 0 : firstSeen; }
    public long lastSeen() { return lastSeen == Long.MIN_VALUE ? 0 : lastSeen; }

    public boolean stale(long now, long ttl) {
        return lastSeen() > 0 && now - lastSeen() > ttl;
    }

    public boolean actionable() {
        return score >= 20 && confidence >= 30;
    }
}
