package com.emailscorer.upwind_home_assignment.business_layer;

import java.util.Map;

import org.springframework.stereotype.Component;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

@Component
public class SuspiciousLinkRule implements SecurityRule {
    @Override
    public RuleResult evaluate(ScoreRequestDTO request) {
        String body = request.getEmailContent();
        
        if (body == null || body.trim().isEmpty()) {
            return new RuleResult(0, null);
        }

        body = body.toLowerCase();
        String[] words = body.split("\\s+"); 

        for (String word : words) {
            if (word.startsWith("http://") || word.startsWith("https://") || word.startsWith("www.")) {
                
                // Loop through the same shared map!
                for (Map.Entry<String, SecurityConstants.RiskLevel> entry : SecurityConstants.TLD_RISK_MAP.entrySet()) {
                    if (word.contains(entry.getKey())) {
                        SecurityConstants.RiskLevel risk = entry.getValue();
                        String explanation = "Body Link -> " + risk.description + " Detected TLD: " + entry.getKey();
                        return new RuleResult(risk.penalty, explanation);
                    }
                }
            }
        }

        return new RuleResult(0, null);
    }
}
