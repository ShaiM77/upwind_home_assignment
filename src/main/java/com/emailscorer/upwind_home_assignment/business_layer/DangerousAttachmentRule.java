package com.emailscorer.upwind_home_assignment.business_layer;

import java.util.List;

import org.springframework.stereotype.Component;
import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

@Component
public class DangerousAttachmentRule implements SecurityRule {
    private static final String[] CRITICAL_EXTENSIONS = { ".exe", ".scr", ".vbs", ".bat", ".js" };
    private static final String[] HIGH_EXTENSIONS = { ".zip", ".rar", ".iso" };
    @Override
    public RuleResult evaluate(ScoreRequestDTO request) {
        List<String> attachments = request.getAttachmentNames();
        
        // If there are no attachments, return a perfect score instantly
        if (attachments == null || attachments.isEmpty()) {
            return new RuleResult(0, null);
        }
        int totalPenalty = 0;
        StringBuilder explanations = new StringBuilder();
        for (String filename : attachments) {
            String lowerName = filename.toLowerCase();
            
            // check for Critical Executables
            for (String ext : CRITICAL_EXTENSIONS) {
                if (lowerName.endsWith(ext)) {
                    totalPenalty += 40;
                    explanations.append("• Attachment -> CRITICAL: Executable file attached: '")
                                .append(filename).append("'\n");
                    break; // we don't want to double-penalize the same file if it matches multiple critical extensions
                }
            }
            
            // check for High-Risk Archives (often used to hide malware)
            for (String ext : HIGH_EXTENSIONS) {
                if (lowerName.endsWith(ext)) {
                    totalPenalty += 25;
                    explanations.append("• Attachment -> HIGH RISK: Archive file attached: '")
                                .append(filename).append("'\n");
                    break;
                }
            }
        }
        if (totalPenalty > 0) {
            return new RuleResult(totalPenalty, explanations.toString());
        }
        return new RuleResult(0, null);
    }
}
