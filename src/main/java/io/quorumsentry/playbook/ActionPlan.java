package io.quorumsentry.playbook;

import io.quorumsentry.detect.Finding;
import java.util.ArrayList;
import java.util.List;

public final class ActionPlan {
    private final List<Action> actions = new ArrayList<>();

    public void add(Action action) {
        actions.add(action);
    }

    public List<Action> actions() {
        return actions;
    }

    public boolean requiresApproval() {
        for (Action action : actions) {
            if (action.destructive()) return true;
        }
        return false;
    }

    public static ActionPlan fromFindings(List<Finding> findings) {
        ActionPlan plan = new ActionPlan();
        for (Finding finding : findings) {
            switch (finding.severity()) {
                case CRITICAL -> plan.add(new Action("isolate", finding.subject()).with("detector", finding.detector()));
                case HIGH -> plan.add(new Action("escalate", finding.subject()).with("detector", finding.detector()));
                case MEDIUM -> plan.add(new Action("watch", finding.subject()).with("detector", finding.detector()));
                default -> plan.add(new Action("note", finding.subject()).with("detector", finding.detector()));
            }
        }
        return plan;
    }
}
