package com.emailscorer.upwind_home_assignment.business_layer;

public class RuleResult {
    private final int penalty;
    private final String reason; //explanation of why the rule was triggered

    public RuleResult(int penalty, String reason) {
        this.penalty = penalty;
        this.reason = reason;
    }

    public int getPenalty() { 
        return penalty; }
    public String getReason() { 
        return reason; }
}
