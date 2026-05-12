package com.emailscorer.upwind_home_assignment.business_layer;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
        
        int totalPenalty = 0;
        StringBuilder reasons = new StringBuilder();
        Set<String> caughtTlds = new HashSet<>();

        for (String word : words) {
            if (word.contains("http://") || word.contains("https://") || word.contains("www.")) {
                for (Map.Entry<String, SecurityConstants.RiskLevel> entry : SecurityConstants.TLD_RISK_MAP.entrySet()) {
                    String tld = entry.getKey();
                    
                    if (word.contains(tld) && !caughtTlds.contains(tld)) {
                        SecurityConstants.RiskLevel risk = entry.getValue();
                        
                        // Added a bullet point visually and the newline character at the end
                        String reason = "• Body Link -> " + risk.description + " Detected TLD: " + tld;
                        
                        totalPenalty += risk.penalty;
                        reasons.append(reason).append("\n"); 
                        
                        caughtTlds.add(tld);
                    }
                }
            }
        }
        
        if (totalPenalty > 0) {
            return new RuleResult(totalPenalty, reasons.toString());
        }
        return new RuleResult(0, null);
    }
}
