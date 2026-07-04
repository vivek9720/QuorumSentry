package io.quorumsentry.engine;

import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.util.IpAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class QuarantinePlanner {
    public Plan plan(List<FlowRecord> flows) {
        Set<String> isolate = new LinkedHashSet<>();
        Set<String> watch = new LinkedHashSet<>();
        if (flows != null) {
            for (FlowRecord flow : flows) {
                if (flow.isLikelyScan() && IpAddress.isPrivate(flow.sourceIp())) {
                    isolate.add(flow.sourceIp());
                } else if (flow.bytesPerPacket() > 50000) {
                    watch.add(flow.sourceIp());
                    watch.add(flow.destinationIp());
                }
            }
        }
        return new Plan(new ArrayList<>(isolate), new ArrayList<>(watch));
    }

    public record Plan(List<String> isolate, List<String> watch) {
        public boolean isEmpty() {
            return isolate.isEmpty() && watch.isEmpty();
        }
    }
}
