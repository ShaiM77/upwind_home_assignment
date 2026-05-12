package com.emailscorer.upwind_home_assignment.business_layer;

import org.springframework.stereotype.Component;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
@Component
public class PhishingTermsRule implements SecurityRule {
private static final String[] PHISHING_TERMS = {
        "urgent", "verify your account", "password", "click here", "bank", "security alert"
    };

    @Override
    public RuleResult evaluate(ScoreRequestDTO request) {
        String content = request.getEmailContent();
        
        // Consistent null return when there's nothing to do
        if (content == null || content.trim().isEmpty()) {
            return new RuleResult(0, null); 
        }

        String lowerContent = content.toLowerCase();
        int totalPenalty = 0;
        StringBuilder explanations = new StringBuilder();
        
        for (String term : PHISHING_TERMS) {
            int count = 0;
            int index = 0;
            String lowerTerm = term.toLowerCase();
            
            while ((index = lowerContent.indexOf(lowerTerm, index)) != -1) {
                count++;
                index += lowerTerm.length();
            }
            
            if (count > 0) {
                totalPenalty += count; // 1 point per phishing term occurrence
                explanations.append(String.format("• Phishing Content -> Detected suspicious phrase: '%s' (%d times, %d points)\n", term, count, count));
            }
        }
        
        if (totalPenalty > 0) {
            return new RuleResult(totalPenalty, explanations.toString());
        }
        
        return new RuleResult(0, null);
    }
}
