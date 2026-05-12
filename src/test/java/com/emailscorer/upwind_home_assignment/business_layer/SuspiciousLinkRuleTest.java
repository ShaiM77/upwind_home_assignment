package com.emailscorer.upwind_home_assignment.business_layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public class SuspiciousLinkRuleTest {
    private SuspiciousLinkRule rule;

    @BeforeEach
    public void setup() {
        rule = new SuspiciousLinkRule();
    }

    // ==================== NULL/EMPTY BODY TESTS ====================

    @Test
    void givenNullBody_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent(null);

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenEmptyBody_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenWhitespaceOnlyBody_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("   \t\n  ");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    // ==================== NO SUSPICIOUS LINKS TESTS ====================

    @Test
    void givenBodyWithoutUrls_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Hello there, this is a regular email without any suspicious links.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenBodyWithSafeHttpUrl_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Visit our website at http://example.com for more info.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenBodyWithSafeHttpsUrl_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Click here: https://google.com for secure browsing.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenBodyWithSafeWwwUrl_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Go to www.microsoft.com for our products.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    // ==================== CRITICAL RISK TLD TESTS ====================

    @Test
    void givenBodyWithHttpCriticalTldZip_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Download the file from http://malware.zip now!");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".zip"));
        assertEquals(true, result.getReason().contains("Body Link ->"));
    }

    @Test
    void givenBodyWithHttpsCriticalTldMov_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Watch this: https://video.mov is important.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".mov"));
    }

    // ==================== HIGH RISK TLD TESTS ====================

    @Test
    void givenBodyWithHttpHighRiskTldTk_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Check http://phish.tk for urgent info.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".tk"));
    }

    @Test
    void givenBodyWithHttpsHighRiskTldMl_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Visit https://scam.ml immediately.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".ml"));
    }

    @Test
    void givenBodyWithWwwHighRiskTldXyz_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Go to www.fake.xyz today.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".xyz"));
    }

    // ==================== MEDIUM RISK TLD TESTS ====================

    @Test
    void givenBodyWithHttpMediumRiskTldLoan_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Apply for a loan at http://quickcash.loan now.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".loan"));
    }

    @Test
    void givenBodyWithHttpsMediumRiskTldFaith_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Our ministry at https://ministry.faith welcomes you.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".faith"));
    }

    @Test
    void givenBodyWithWwwMediumRiskTldOnline_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Stream videos at www.streaming.online unlimited.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".online"));
    }

    // ==================== CASE INSENSITIVITY TESTS ====================

    @Test
    void givenBodyWithMixedCaseUrl_whenEvaluate_thenDetectsSuspiciousTld() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Visit HTTP://EXAMPLE.TK for details.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenBodyWithUrlInMixedCase_whenEvaluate_thenDetectsSuspiciousTld() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Go to https://PHISHING.ML now.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // ==================== MULTIPLE URLS TEST ====================

    @Test
    void givenBodyWithMultipleSuspiciousUrls_whenEvaluate_thenReturnsFirstMatch() {
        // Arrange - has both .zip (critical, 40) and .tk (high, 25), should return on first match
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Download from http://file.zip or visit http://site.tk");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert - should match .zip first and return 40 penalty
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".zip"));
    }

    @Test
    void givenBodyWithMixedSafeAndSuspiciousUrls_whenEvaluate_thenReturnsPenaltyForSuspicious() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Visit http://google.com and then check http://malware.loan");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".loan"));
    }

    // ==================== URL PREFIX COMBINATION TESTS ====================

    @Test
    void givenBodyWithHttp_whenEvaluate_thenDetectsSuspiciousLink() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("http://badsite.cf");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenBodyWithHttps_whenEvaluate_thenDetectsSuspiciousLink() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("https://badsite.ga");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenBodyWithWww_whenEvaluate_thenDetectsSuspiciousLink() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("www.badsite.gq");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // ==================== EDGE CASES ====================

    @Test
    void givenBodyWithUrlNoTld_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Visit http://localhost or https://internal");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenBodyWithMultipleWords_whenEvaluate_thenSplitsAndChecksCorrectly() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Please visit http://example.tk today and confirm.");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenBodyWithUrlPartialMatch_whenEvaluate_thenDetectsContainedTld() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("http://verify.accountant is waiting");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".accountant"));
    }
}
