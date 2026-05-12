package com.emailscorer.upwind_home_assignment.business_layer;
import java.util.Map;
import org.springframework.stereotype.Component;
import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
@Component
public class SuspiciousSenderTldRule implements SecurityRule {
    @Override
    public RuleResult evaluate(ScoreRequestDTO request) {
        String email = extractEmailAddress(request.getSender()).toLowerCase();
        
        // Loop through the shared map
        for (Map.Entry<String, SecurityConstants.RiskLevel> entry : SecurityConstants.TLD_RISK_MAP.entrySet()) {
            if (email.endsWith(entry.getKey())) {
                SecurityConstants.RiskLevel risk = entry.getValue();
                String reason = "Sender Identity -> " + risk.description + " Detected TLD: " + entry.getKey() +"\n";
                return new RuleResult(risk.penalty, reason);
            }
        }

        return new RuleResult(0, null);
    }
    
}
