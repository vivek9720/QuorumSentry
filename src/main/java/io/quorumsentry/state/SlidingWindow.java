package io.quorumsentry.state;

import java.util.ArrayDeque;
import java.util.Deque;

public final class SlidingWindow {
    private final long widthMillis;
    private final Deque<Point> points = new ArrayDeque<>();
    private long sum;

    public SlidingWindow(long widthMillis) {
        this.widthMillis = Math.max(1, widthMillis);
    }

    public void add(long time, long value) {
        points.addLast(new Point(time, value));
        sum += value;
        evict(time);
    }

    public long sum(long now) {
        evict(now);
        return sum;
    }

    public double rate(long now) {
        return (double) sum(now) / (double) widthMillis;
    }

    private void evict(long now) {
        while (!points.isEmpty() && now - points.peekFirst().time > widthMillis) {
            sum -= points.removeFirst().value;
        }
    }

    private record Point(long time, long value) {}
}
