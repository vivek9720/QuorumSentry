package io.quorumsentry.state;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import java.util.HashMap;
import java.util.Map;

public final class HostLedger {
    private final Map<String, SlidingWindow> eventRates = new HashMap<>();
    private final Map<String, SlidingWindow> byteRates = new HashMap<>();

    public void observe(EventRecord event) {
        eventRates.computeIfAbsent(event.host(), h -> new SlidingWindow(300_000)).add(event.timestamp(), event.severity().weight());
    }

    public void observe(FlowRecord flow) {
        byteRates.computeIfAbsent(flow.sourceIp(), h -> new SlidingWindow(300_000)).add(flow.lastSeen(), flow.bytes());
    }

    public long eventScore(String host, long now) {
        SlidingWindow window = eventRates.get(host);
        return window == null ? 0 : window.sum(now);
    }

    public long bytesFrom(String host, long now) {
        SlidingWindow window = byteRates.get(host);
        return window == null ? 0 : window.sum(now);
    }
}
