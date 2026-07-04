package io.quorumsentry.playbook;

import java.util.LinkedHashMap;
import java.util.Map;

public final class Action {
    private final String verb;
    private final String target;
    private final Map<String, String> parameters = new LinkedHashMap<>();

    public Action(String verb, String target) {
        this.verb = verb;
        this.target = target;
    }

    public Action with(String key, Object value) {
        parameters.put(key, String.valueOf(value));
        return this;
    }

    public String verb() { return verb; }
    public String target() { return target; }
    public Map<String, String> parameters() { return parameters; }

    public boolean destructive() {
        return "isolate".equals(verb) || "disable".equals(verb) || "block".equals(verb);
    }
}
