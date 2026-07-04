package io.quorumsentry.policy;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Policy {
    private final String name;
    private final List<Rule> rules;

    public Policy(String name, List<Rule> rules) {
        this.name = name == null ? "unnamed" : name;
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
    }

    public String name() { return name; }
    public List<Rule> rules() { return rules; }

    public List<Rule> evaluate(EventRecord event) {
        List<Rule> hits = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.matches(event)) {
                hits.add(rule);
            }
        }
        return hits;
    }

    public List<Rule> evaluate(FlowRecord flow) {
        List<Rule> hits = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.matches(flow)) {
                hits.add(rule);
            }
        }
        return hits;
    }
}
