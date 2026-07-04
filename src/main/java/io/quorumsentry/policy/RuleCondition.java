package io.quorumsentry.policy;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

public final class RuleCondition {
    private final String expression;
    private final Predicate<EventRecord> eventPredicate;
    private final Predicate<FlowRecord> flowPredicate;

    private RuleCondition(String expression, Predicate<EventRecord> eventPredicate, Predicate<FlowRecord> flowPredicate) {
        this.expression = expression;
        this.eventPredicate = eventPredicate;
        this.flowPredicate = flowPredicate;
    }

    public static RuleCondition parse(String expression) {
        String[] parts = expression.split("\\s+and\\s+");
        List<RuleCondition> terms = new ArrayList<>();
        for (String part : parts) {
            terms.add(single(part.trim()));
        }
        return new RuleCondition(expression, e -> {
            for (RuleCondition c : terms) if (!c.matches(e)) return false;
            return true;
        }, f -> {
            for (RuleCondition c : terms) if (!c.matches(f)) return false;
            return true;
        });
    }

    private static RuleCondition single(String expression) {
        String[] p = expression.split("\\s+", 3);
        String field = p.length > 0 ? p[0].toLowerCase(Locale.ROOT) : "";
        String op = p.length > 1 ? p[1] : "";
        String value = p.length > 2 ? p[2].replace("\"", "") : "";
        if (field.equals("severity")) {
            Severity threshold = Severity.fromText(value);
            return new RuleCondition(expression, e -> compare(e.severity().weight(), op, threshold.weight()), f -> false);
        }
        if (field.equals("message")) {
            return new RuleCondition(expression, e -> e.message().toLowerCase().contains(value.toLowerCase()), f -> false);
        }
        if (field.equals("category")) {
            return new RuleCondition(expression, e -> e.category().equalsIgnoreCase(value), f -> false);
        }
        if (field.equals("dport")) {
            int port = Integer.parseInt(value);
            return new RuleCondition(expression, e -> false, f -> compare(f.destinationPort(), op, port));
        }
        if (field.equals("bytes")) {
            long bytes = Long.parseLong(value);
            return new RuleCondition(expression, e -> false, f -> compare(f.bytes(), op, bytes));
        }
        if (field.equals("proto")) {
            return new RuleCondition(expression, e -> false, f -> f.protocol().equalsIgnoreCase(value));
        }
        return new RuleCondition(expression, e -> e.attribute(field).equals(value), f -> value.equals(f.tags().get(field)));
    }

    private static boolean compare(long left, String op, long right) {
        return switch (op) {
            case ">", "gt" -> left > right;
            case ">=", "gte" -> left >= right;
            case "<", "lt" -> left < right;
            case "<=", "lte" -> left <= right;
            case "!=", "ne" -> left != right;
            default -> left == right;
        };
    }

    public boolean matches(EventRecord event) {
        return eventPredicate.test(event);
    }

    public boolean matches(FlowRecord flow) {
        return flowPredicate.test(flow);
    }

    public String expression() {
        return expression;
    }
}
