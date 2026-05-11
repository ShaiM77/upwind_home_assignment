package com.emailscorer.upwind_home_assignment.business_layer;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public interface SecurityRule {
    RuleResult evaluate(ScoreRequestDTO request);
    // helper method to extract email address from headers, can be used by multiple rules
    default String extractEmailAddress(String rawHeader) {
        if (rawHeader == null) return "";
        int start = rawHeader.indexOf('<');
        int end = rawHeader.indexOf('>');
        if (start != -1 && end != -1 && end > start) {
            return rawHeader.substring(start + 1, end).trim().toLowerCase();
        }
        return rawHeader.trim().toLowerCase();
    }
}
