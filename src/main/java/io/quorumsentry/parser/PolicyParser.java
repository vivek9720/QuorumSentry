package io.quorumsentry.parser;

import io.quorumsentry.core.ParseException;
import io.quorumsentry.policy.Policy;
import io.quorumsentry.policy.Rule;
import io.quorumsentry.policy.RuleAction;
import io.quorumsentry.policy.RuleCondition;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class PolicyParser {
    public Policy parse(byte[] data) {
        String text = new String(data == null ? new byte[0] : data, StandardCharsets.UTF_8);
        String name = "unnamed";
        List<Rule> rules = new ArrayList<>();
        int lineNo = 0;
        for (String raw : text.split("\\r?\\n")) {
            lineNo++;
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("policy ")) {
                name = line.substring(7).trim();
                continue;
            }
            if (!line.startsWith("rule ")) {
                throw new ParseException("unknown policy statement at line " + lineNo);
            }
            rules.add(parseRule(line.substring(5).trim(), lineNo));
        }
        if (rules.isEmpty()) {
            throw new ParseException("policy has no rules");
        }
        return new Policy(name, rules);
    }

    private Rule parseRule(String text, int lineNo) {
        int when = text.indexOf(" when ");
        int then = text.indexOf(" then ");
        if (when <= 0 || then <= when) {
            throw new ParseException("bad rule syntax at line " + lineNo);
        }
        String name = text.substring(0, when).trim();
        String conditionText = text.substring(when + 6, then).trim();
        String actionText = text.substring(then + 6).trim();
        RuleCondition condition = RuleCondition.parse(conditionText);
        RuleAction action = RuleAction.parse(actionText);
        return new Rule(name, condition, action);
    }
}
