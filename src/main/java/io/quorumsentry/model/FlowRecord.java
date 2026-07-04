package io.quorumsentry.model;

import java.util.LinkedHashMap;
import java.util.Map;

public final class FlowRecord {
    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;
    private final long packets;
    private final long bytes;
    private final long firstSeen;
    private final long lastSeen;
    private final Map<String, String> tags = new LinkedHashMap<>();

    public FlowRecord(String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol, long packets, long bytes, long firstSeen, long lastSeen) {
        this.sourceIp = sourceIp == null ? "0.0.0.0" : sourceIp;
        this.destinationIp = destinationIp == null ? "0.0.0.0" : destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol == null ? "tcp" : protocol.toLowerCase();
        this.packets = Math.max(0, packets);
        this.bytes = Math.max(0, bytes);
        this.firstSeen = firstSeen;
        this.lastSeen = Math.max(firstSeen, lastSeen);
    }

    public String sourceIp() { return sourceIp; }
    public String destinationIp() { return destinationIp; }
    public int sourcePort() { return sourcePort; }
    public int destinationPort() { return destinationPort; }
    public String protocol() { return protocol; }
    public long packets() { return packets; }
    public long bytes() { return bytes; }
    public long firstSeen() { return firstSeen; }
    public long lastSeen() { return lastSeen; }
    public Map<String, String> tags() { return tags; }

    public long durationMillis() {
        return Math.max(1L, lastSeen - firstSeen);
    }

    public double bytesPerPacket() {
        return packets == 0 ? 0.0 : (double) bytes / (double) packets;
    }

    public boolean isPrivilegedDestination() {
        return destinationPort > 0 && destinationPort < 1024;
    }

    public boolean isLikelyScan() {
        return packets <= 3 && bytes < 200 && isPrivilegedDestination();
    }
}
