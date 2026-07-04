package io.quorumsentry.playbook;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class CaseTimeline {
    private final List<Entry> entries = new ArrayList<>();

    public void add(long timestamp, String actor, String message) {
        entries.add(new Entry(timestamp, actor, message));
    }

    public List<Entry> ordered() {
        entries.sort(Comparator.comparingLong(Entry::timestamp));
        return entries;
    }

    public String render() {
        StringBuilder out = new StringBuilder();
        for (Entry entry : ordered()) {
            out.append(entry.timestamp()).append(' ')
               .append(entry.actor()).append(' ')
               .append(entry.message()).append('\n');
        }
        return out.toString();
    }

    public record Entry(long timestamp, String actor, String message) {}
}
