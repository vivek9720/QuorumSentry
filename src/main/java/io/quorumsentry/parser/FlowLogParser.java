package io.quorumsentry.parser;

import io.quorumsentry.core.ParseException;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.util.IpAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class FlowLogParser {
    public List<FlowRecord> parse(byte[] data) {
        String text = new String(data == null ? new byte[0] : data, StandardCharsets.UTF_8);
        List<FlowRecord> flows = new ArrayList<>();
        for (String raw : text.split("\\r?\\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            flows.add(parseLine(line));
        }
        if (flows.isEmpty()) {
            throw new ParseException("no flow rows");
        }
        return flows;
    }

    private FlowRecord parseLine(String line) {
        String[] p = line.split(",");
        if (p.length < 9) {
            throw new ParseException("flow row has " + p.length + " fields");
        }
        String src = p[0].trim();
        String dst = p[1].trim();
        int sport = Integer.parseInt(p[2].trim());
        int dport = Integer.parseInt(p[3].trim());
        String proto = p[4].trim();
        long packets = Long.parseLong(p[5].trim());
        long bytes = Long.parseLong(p[6].trim());
        long first = Long.parseLong(p[7].trim());
        long last = Long.parseLong(p[8].trim());
        FlowRecord flow = new FlowRecord(src, dst, sport, dport, proto, packets, bytes, first, last);
        if (IpAddress.isPrivate(src)) {
            flow.tags().put("src_zone", "private");
        }
        if (IpAddress.isPrivate(dst)) {
            flow.tags().put("dst_zone", "private");
        }
        if (proto.equalsIgnoreCase("udp") && dport == 53 && p.length > 9) {
            applyDnsSketch(flow, p[9]);
        }
        return flow;
    }

    private void applyDnsSketch(FlowRecord flow, String sketch) {
        String[] labels = sketch.split("\\.");
        int[] counters = new int[6];
        for (String label : labels) {
            if (label.startsWith("_qs")) {
                int bucket = Integer.parseInt(label.substring(3));
                counters[bucket]++;
            }
        }
        int max = 0;
        for (int c : counters) {
            max = Math.max(max, c);
        }
        if (max > 2) {
            flow.tags().put("dns_tunnel_hint", "true");
        }
    }
}
