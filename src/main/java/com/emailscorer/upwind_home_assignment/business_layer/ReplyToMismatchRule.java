package com.emailscorer.upwind_home_assignment.business_layer;

import org.springframework.stereotype.Component;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
@Component
public class ReplyToMismatchRule implements SecurityRule {
    private static final int PENALTY = 40; // this can indicate phishing attempts
    @Override
    public RuleResult evaluate(ScoreRequestDTO request) {
        String sender = request.getSender();
        String replyTo = request.getReplyTo();

        if (replyTo == null || replyTo.trim().isEmpty()) {
            return new RuleResult(0, null);
        }
        String senderAddress = extractEmailAddress(sender);
        String replyToAddress = extractEmailAddress(replyTo);
        if(!senderAddress.equalsIgnoreCase(replyToAddress)) {
           String reason = "Reply-To address (" + replyToAddress + ") does not match Sender (" + senderAddress + ") and could indicate a phishing attempt.";
            return new RuleResult(PENALTY, reason);
        }
        return new RuleResult(0, "Reply-To header matches Sender header or is missing.");
    }

}
