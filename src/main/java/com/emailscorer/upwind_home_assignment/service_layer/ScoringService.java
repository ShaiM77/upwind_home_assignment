package com.emailscorer.upwind_home_assignment.service_layer;


import com.emailscorer.upwind_home_assignment.business_layer.ReplyToMismatchRule;
import com.emailscorer.upwind_home_assignment.business_layer.RuleResult;
import com.emailscorer.upwind_home_assignment.business_layer.SecurityRule;
import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
import com.emailscorer.upwind_home_assignment.dto.ScoreResultDTO;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ScoringService {

    // Spring injects all your @Component rules here automatically
    private final List<SecurityRule> rules;
    private static final Logger logger = LoggerFactory.getLogger(ScoringService.class);

    public ScoringService(List<SecurityRule> rules) {
        this.rules = rules;
    }

    public ScoreResultDTO analyze(ScoreRequestDTO request) {
        // sanitizing the email's body to prevent XSS
        request.setEmailContent(sanitizeInput(request.getEmailContent()));
        int score = 100;
        List<String> rawReasons = new ArrayList<>();
        for (SecurityRule rule : rules) {
            RuleResult result = rule.evaluate(request);
            if (result.getPenalty() > 0) {
                score -= result.getPenalty();
                rawReasons.add(result.getReason()); 
                logger.warn("Rule violation detected: {}", result.getReason());
            }
        }
        // final score can't be below 0
        int finalScore = Math.max(0, score);
        String verdict = finalScore < 70 ? "Malicious" : "Safe";
        logger.info("Finished analysis. Final Verdict: {}, Score: {}, Violations detected: {}", verdict, finalScore, rawReasons.size());

        // we sanitize the reasons ensuring the UI does not render any malicious content.
        List<String> safeReasons = new ArrayList<>();
        for (String reason : rawReasons) {
            safeReasons.add(sanitizeInput(reason));
        }
        return new ScoreResultDTO(finalScore, verdict, safeReasons);
    }

    private String sanitizeInput(String input) {
        if (input == null) return "";
        // &lt; and &gt; are traditional HTML entity encodings for < and > we encode them to prevent any malicious HTML/JS from being rendered in the UI.
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

