package io.quorumsentry.signature;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.ThreatIndicator;
import java.util.ArrayList;
import java.util.List;

public final class SignatureMatcher {
    private final AhoTrie trie = new AhoTrie();
    private final List<ThreatIndicator> indicators = new ArrayList<>();
    private boolean built;

    public void add(ThreatIndicator indicator) {
        indicators.add(indicator);
        if (!indicator.value().isBlank()) {
            trie.add(indicator.value(), indicator.id());
        }
        built = false;
    }

    public List<ThreatIndicator> match(EventRecord event) {
        if (!built) {
            trie.build();
            built = true;
        }
        List<String> ids = trie.find(event.message());
        List<ThreatIndicator> out = new ArrayList<>();
        for (ThreatIndicator indicator : indicators) {
            if (ids.contains(indicator.id()) || indicator.matchesText(event.message())) {
                out.add(indicator);
            }
        }
        return out;
    }
}
