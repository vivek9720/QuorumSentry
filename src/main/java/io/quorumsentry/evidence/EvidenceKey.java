package io.quorumsentry.evidence;

import io.quorumsentry.util.TokenNormalizer;

public final class EvidenceKey implements Comparable<EvidenceKey> {
    private final String kind;
    private final String value;
    private final int bucket;

    public EvidenceKey(String kind, String value) {
        this.kind = TokenNormalizer.token(kind);
        this.value = TokenNormalizer.token(value);
        this.bucket = TokenNormalizer.stableBucket(this.kind + ":" + this.value, 1024);
    }

    public String kind() { return kind; }
    public String value() { return value; }
    public int bucket() { return bucket; }

    public boolean sameKind(EvidenceKey other) {
        return other != null && kind.equals(other.kind);
    }

    public boolean isEmpty() {
        return kind.isEmpty() || value.isEmpty();
    }

    public String compact() {
        return kind + ":" + value;
    }

    @Override
    public int compareTo(EvidenceKey other) {
        int byKind = kind.compareTo(other.kind);
        return byKind != 0 ? byKind : value.compareTo(other.value);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof EvidenceKey other)) return false;
        return kind.equals(other.kind) && value.equals(other.value);
    }

    @Override
    public int hashCode() {
        return 31 * kind.hashCode() + value.hashCode();
    }

    @Override
    public String toString() {
        return compact();
    }
}
