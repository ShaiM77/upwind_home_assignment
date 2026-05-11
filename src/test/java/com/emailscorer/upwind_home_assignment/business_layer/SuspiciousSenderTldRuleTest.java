package com.emailscorer.upwind_home_assignment.business_layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.emailscorer.upwind_home_assignment.business_layer.RuleResult;
import com.emailscorer.upwind_home_assignment.business_layer.SuspiciousSenderTldRule;
import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public class SuspiciousSenderTldRuleTest {
    private SuspiciousSenderTldRule rule;

    @BeforeEach
    public void setup() {
        rule = new SuspiciousSenderTldRule();
    }

    // ==================== SAFE TLD TESTS ====================

    @Test
    void givenSenderWithSafeTld_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("user@example.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenSenderFromGmail_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("legitimate@gmail.com");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenSenderFromCompanyDomain_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("boss@mycompany.org");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    // ==================== CRITICAL RISK TLD TESTS ====================

    @Test
    void givenSenderWithCriticalTldZip_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("attacker@malware.zip");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".zip"));
        assertEquals(true, result.getReason().contains("Sender Identity ->"));
    }

    @Test
    void givenSenderWithCriticalTldMov_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("hacker@suspicious.mov");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".mov"));
    }

    // ==================== HIGH RISK TLD TESTS ====================

    @Test
    void givenSenderWithHighRiskTldTk_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("suspicious@phishing.tk");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".tk"));
    }

    @Test
    void givenSenderWithHighRiskTldMl_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("fake@spam.ml");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".ml"));
    }

    @Test
    void givenSenderWithHighRiskTldGa_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("attacker@scam.ga");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".ga"));
    }

    @Test
    void givenSenderWithHighRiskTldCf_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("hacker@free.cf");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".cf"));
    }

    @Test
    void givenSenderWithHighRiskTldGq_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("spammer@anonymous.gq");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".gq"));
    }

    @Test
    void givenSenderWithHighRiskTldXyz_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("fraud@badactor.xyz");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".xyz"));
    }

    @Test
    void givenSenderWithHighRiskTldTop_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("unknown@mystery.top");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".top"));
    }

    @Test
    void givenSenderWithHighRiskTldIcu_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("attacker@spam.icu");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".icu"));
    }

    // ==================== MEDIUM RISK TLD TESTS ====================

    @Test
    void givenSenderWithMediumRiskTldLoan_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("lender@quickcash.loan");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".loan"));
    }

    @Test
    void givenSenderWithMediumRiskTldFaith_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("pastor@ministry.faith");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".faith"));
    }

    @Test
    void givenSenderWithMediumRiskTldAccountant_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("tax@taxhelp.accountant");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".accountant"));
    }

    @Test
    void givenSenderWithMediumRiskTldRacing_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("bettor@sportsbet.racing");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".racing"));
    }

    @Test
    void givenSenderWithMediumRiskTldCricket_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("fan@cricket.cricket");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".cricket"));
    }

    @Test
    void givenSenderWithMediumRiskTldMen_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("contact@singles.men");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".men"));
    }

    @Test
    void givenSenderWithMediumRiskTldStream_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("user@movies.stream");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".stream"));
    }

    @Test
    void givenSenderWithMediumRiskTldOnline_whenEvaluate_thenReturnsMediumPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("admin@shop.online");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(15, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".online"));
    }

    // ==================== CASE INSENSITIVITY TESTS ====================

    @Test
    void givenSenderWithMixedCaseRiskyTld_whenEvaluate_thenDetectsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("user@example.TK");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenSenderWithUppercaseRiskyTld_whenEvaluate_thenDetectsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("USER@EXAMPLE.ML");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // ==================== HEADER PARSING TESTS ====================

    @Test
    void givenSenderInAngleBracketsWithRiskyTld_whenEvaluate_thenDetectsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("Attacker Name <attacker@evil.tk>");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".tk"));
    }

    @Test
    void givenSenderWithJustEmailInBrackets_whenEvaluate_thenDetectsPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("<malicious@dangerous.zip>");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // ==================== NULL SENDER TESTS ====================

    @Test
    void givenNullSender_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender(null);

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenEmptySender_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    // ==================== REASON MESSAGE TESTS ====================

    @Test
    void givenRiskyTldDetected_whenEvaluate_thenReasonContainsTldAndDescription() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("admin@freehost.ga");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        String reason = result.getReason();
        assertEquals(true, reason.contains(".ga"));
        assertEquals(true, reason.contains("Detected TLD"));
        assertEquals(true, reason.contains("Sender Identity ->"));
    }

    @Test
    void givenCriticalRiskyTld_whenEvaluate_thenReasonIncludesDescription() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("hacker@package.zip");

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        String reason = result.getReason();
        assertEquals(true, reason.contains("Extreme risk"));
        assertEquals(true, reason.contains(".zip"));
    }
}
