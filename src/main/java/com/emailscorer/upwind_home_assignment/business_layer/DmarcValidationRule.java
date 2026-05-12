package com.emailscorer.upwind_home_assignment.business_layer;

import org.springframework.stereotype.Component;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
@Component
public class DmarcValidationRule implements SecurityRule {
    private static final int PENALTY = 50; // DMARC failure is a strong indicator of spoofing

    @Override
    public RuleResult evaluate(ScoreRequestDTO request) {
        if (request.isDmarcFailed()) {
            return new RuleResult(PENALTY, "• Authentication -> CRITICAL: DMARC verification failed. The sender address is likely spoofed.\n");
        }
        return new RuleResult(0, null);
    }

}
