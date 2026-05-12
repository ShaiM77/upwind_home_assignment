package com.emailscorer.upwind_home_assignment.business_layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public class PhishingTermsRuleTest {
    private PhishingTermsRule rule;

    @BeforeEach
    public void setup() {
        rule = new PhishingTermsRule();
    }

    // ==================== NULL/EMPTY TESTS ====================

    @Test
    void givenNullContent_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent(null);

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNull(result.getReason());
    }

    @Test
    void givenEmptyContent_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent("");

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNull(result.getReason());
    }

    // ==================== SAFE CONTENT TESTS ====================

    @Test
    void givenNoPhishingTerms_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent("Hello, this is a perfectly safe email about our meeting.");

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNull(result.getReason());
    }

    // ==================== PENALTY TESTS ====================

    @Test
    void givenSinglePhishingTerm_whenEvaluate_thenReturnsSinglePenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent("This is urgent. Please respond.");

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(1, result.getPenalty());
        assertTrue(result.getReason().contains("urgent"));
    }

    @Test
    void givenMultipleDifferentPhishingTerms_whenEvaluate_thenCumulatesPenalties() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent("Urgent! Please verify your account and password. Click here for your bank security alert.");

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(6, result.getPenalty());
        assertTrue(result.getReason().contains("urgent"));
        assertTrue(result.getReason().contains("verify your account"));
        assertTrue(result.getReason().contains("password"));
        assertTrue(result.getReason().contains("click here"));
        assertTrue(result.getReason().contains("bank"));
        assertTrue(result.getReason().contains("security alert"));
    }

    @Test
    void givenMultipleOccurrencesOfSameTerm_whenEvaluate_thenCountsEachOccurrence() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent("urgent urgent urgent");

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(3, result.getPenalty());
        assertTrue(result.getReason().contains("urgent"));
    }

    // ==================== CASE INSENSITIVITY TESTS ====================

    @Test
    void givenUppercasePhishingTerms_whenEvaluate_thenMatchesCaseInsensitively() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setEmailContent("URGENT! Please VERIFY YOUR ACCOUNT.");

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(2, result.getPenalty());
        assertTrue(result.getReason().toLowerCase().contains("urgent"));
        assertTrue(result.getReason().toLowerCase().contains("verify your account"));
    }
}
