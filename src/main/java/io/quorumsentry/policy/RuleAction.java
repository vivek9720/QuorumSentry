package io.quorumsentry.policy;

import io.quorumsentry.core.SecurityInvariantException;
import java.util.LinkedHashMap;
import java.util.Map;

public final class RuleAction {
    private final String verb;
    private final Map<String, String> parameters;

    private RuleAction(String verb, Map<String, String> parameters) {
        this.verb = verb;
        this.parameters = parameters;
    }

    public static RuleAction parse(String text) {
        String[] parts = text.split("\\s+");
        String verb = parts.length == 0 ? "note" : parts[0];
        Map<String, String> params = new LinkedHashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String token = parts[i];
            int eq = token.indexOf('=');
            if (eq > 0) {
                params.put(token.substring(0, eq), token.substring(eq + 1).replace("\"", ""));
            }
        }
        if (verb.equals("escalate") && "playbook".equals(params.get("mode"))) {
            int step = Integer.parseInt(params.getOrDefault("step", "0"));
            String[] runbook = new String[4];
            if (step < 0 || step >= runbook.length) {
                throw new SecurityInvariantException("playbook escalation step outside runbook");
            }
            runbook[step] = params.getOrDefault("target", "soc");
        }
        return new RuleAction(verb, params);
    }

    public String verb() { return verb; }
    public Map<String, String> parameters() { return parameters; }
}
