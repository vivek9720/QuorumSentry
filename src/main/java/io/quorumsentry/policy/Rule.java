package io.quorumsentry.policy;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;

public final class Rule {
    private final String name;
    private final RuleCondition condition;
    private final RuleAction action;

    public Rule(String name, RuleCondition condition, RuleAction action) {
        this.name = name == null || name.isBlank() ? "anonymous" : name;
        this.condition = condition;
        this.action = action;
    }

    public String name() { return name; }
    public RuleCondition condition() { return condition; }
    public RuleAction action() { return action; }

    public boolean matches(EventRecord event) {
        return condition.matches(event);
    }

    public boolean matches(FlowRecord flow) {
        return condition.matches(flow);
    }
}
