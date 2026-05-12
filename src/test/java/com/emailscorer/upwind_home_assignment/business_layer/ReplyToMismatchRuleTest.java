package com.emailscorer.upwind_home_assignment.business_layer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.emailscorer.upwind_home_assignment.business_layer.ReplyToMismatchRule;
import com.emailscorer.upwind_home_assignment.business_layer.RuleResult;
import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public class ReplyToMismatchRuleTest {
    private ReplyToMismatchRule rule;

    @BeforeEach
    public void setup() {
        rule = new ReplyToMismatchRule();
    }

    // null/empty Reply-To tests

    @Test
    void givenNullReplyTo_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("sender@example.com");
        request.setReplyTo(null);

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenEmptyReplyTo_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("sender@example.com");
        request.setReplyTo("");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenWhitespaceOnlyReplyTo_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("sender@example.com");
        request.setReplyTo("   \t\n  ");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    //matching addresses tests

    @Test
    void givenMatchingSenderAndReplyToSimple_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("user@example.com");
        request.setReplyTo("user@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("matches"));
    }

    @Test
    void givenMatchingAddressInAngleBrackets_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("John Doe <john@company.com>");
        request.setReplyTo("john@company.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("matches"));
    }

    @Test
    void givenBothAddressesInAngleBrackets_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("Alice <alice@corp.com>");
        request.setReplyTo("Alice <alice@corp.com>");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("matches"));
    }

    @Test
    void givenCaseDifferenceInAddress_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("User@EXAMPLE.COM");
        request.setReplyTo("user@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenMixedCaseInBrackets_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("<Test@Example.Com>");
        request.setReplyTo("<test@example.com>");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // mismatching addresses tests

    @Test
    void givenDifferentSenderAndReplyTo_whenEvaluate_thenReturnsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("legitimate@company.com");
        request.setReplyTo("attacker@phishing.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("does not match"));
        assertEquals(true, result.getReason().contains("phishing"));
    }

    @Test
    void givenMismatchWithBrackets_whenEvaluate_thenReturnsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("Boss <boss@company.com>");
        request.setReplyTo("Fake <fake@evil.com>");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("does not match"));
    }

    @Test
    void givenMismatchCaseDifference_whenEvaluate_thenReturnsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("user1@example.com");
        request.setReplyTo("USER2@EXAMPLE.COM");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenMismatchOneDomainDifferent_whenEvaluate_thenReturnsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("support@company1.com");
        request.setReplyTo("support@company2.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // header parsing edge cases

    @Test
    void givenSenderWithoutBrackets_whenEvaluate_thenExtractsAddressCorrectly() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("test@domain.com");
        request.setReplyTo("test@domain.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
    }

    @Test
    void givenSenderWithIncompleteBrackets_whenEvaluate_thenHandlesGracefully() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("<incomplete");
        request.setReplyTo("<incomplete");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        // Should match since both parse to the same string
        assertEquals(0, result.getPenalty());
    }

    @Test
    void givenAddressWithSpacesInBrackets_whenEvaluate_thenTrimsCorrectly() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("< user@example.com >");
        request.setReplyTo("user@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
    }

    @Test
    void givenBothAddressesWithExtraSpaces_whenEvaluate_thenTrimsAndMatches() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("  < sender@test.com >  ");
        request.setReplyTo("  sender@test.com  ");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
    }

    // NULL/EMPTY sender tests

    @Test
    void givenNullSender_whenEvaluate_thenHandlesGracefully() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender(null);
        request.setReplyTo("attacker@evil.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenEmptySender_whenEvaluate_thenReturnsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("");
        request.setReplyTo("user@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // reason message content tests

    @Test
    void givenMismatchDetected_whenEvaluate_thenReasonContainsAddresses() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("legitimate@company.com");
        request.setReplyTo("hacker@malicious.net");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        String reason = result.getReason();
        assertEquals(true, reason.contains("hacker@malicious.net"));
        assertEquals(true, reason.contains("legitimate@company.com"));
    }

    // edge cases

    @Test
    void givenOnlyOpenBracketInSender_whenEvaluate_thenDetectsMismatch() {
        // Arrange - incomplete bracket means email is not properly extracted
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("<test@example.com");
        request.setReplyTo("test@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert - mismatches because "<test@example.com" != "test@example.com"
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenOnlyCloseBracketInSender_whenEvaluate_thenDetectsMismatch() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("test@example.com>");
        request.setReplyTo("test@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert - mismatches because "test@example.com>" != "test@example.com"
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenReversedBracketsInSender_whenEvaluate_thenDetectsMismatch() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender(">test@example.com<");
        request.setReplyTo("test@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert - mismatches because end < start (> is before <)
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenMultipleBracketsInSender_whenEvaluate_thenExtractsFirstPair() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("John <john@example.com> <backup>");
        request.setReplyTo("john@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
    }

    @Test
    void givenReplyToWithOnlyOpenBracket_whenEvaluate_thenMismatchDetected() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("user@example.com");
        request.setReplyTo("<other@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
    }

    @Test
    void givenBothAddressesFormattedIdentically_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("Support Team <support@acme.com>");
        request.setReplyTo("Support Desk <support@acme.com>");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenWhitespaceInBrackets_whenEvaluate_thenTrimsAndMatches() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("<  admin@site.com  >");
        request.setReplyTo("admin@site.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
    }

    @Test
    void givenAllUppercaseExtraction_whenEvaluate_thenNormalizes() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("ADMIN@SITE.COM");
        request.setReplyTo("admin@site.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
    }
}
