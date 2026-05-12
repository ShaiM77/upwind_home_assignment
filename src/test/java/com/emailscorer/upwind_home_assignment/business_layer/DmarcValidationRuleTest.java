package com.emailscorer.upwind_home_assignment.business_layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public class DmarcValidationRuleTest {
    private DmarcValidationRule rule;

    @BeforeEach
    public void setup() {
        rule = new DmarcValidationRule();
    }

    // ==================== PENALTY TESTS ====================

    @Test
    void givenDmarcFailed_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setDmarcFailed(true);

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(50, result.getPenalty());
        assertNotNull(result.getReason());
        assertTrue(result.getReason().contains("DMARC verification failed"));
        assertTrue(result.getReason().contains("CRITICAL"));
    }

    // ==================== SAFE TESTS ====================

    @Test
    void givenDmarcPassed_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setDmarcFailed(false);

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNull(result.getReason());
    }

    // ==================== DEFAULT STATE TESTS ====================

    @Test
    void givenDefaultDto_whenEvaluate_thenDefaultsToNoPenalty() {
        // Arrange
        ScoreRequestDTO dto = new ScoreRequestDTO(); 
        // In Java, primitive booleans default to 'false'. 
        // We want to ensure an empty DTO doesn't accidentally trigger the 50-point penalty.

        // Act
        RuleResult result = rule.evaluate(dto);

        // Assert
        assertEquals(0, result.getPenalty());
        assertNull(result.getReason());
    }
}
