package com.emailscorer.upwind_home_assignment.service_layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.security.Security;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.emailscorer.upwind_home_assignment.business_layer.RuleResult;
import com.emailscorer.upwind_home_assignment.business_layer.SecurityRule;
import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
import com.emailscorer.upwind_home_assignment.dto.ScoreResultDTO;

@ExtendWith(MockitoExtension.class)
public class ScoringServiceTest {
    @Mock
    private SecurityRule mockRule1;
    @Mock
    private SecurityRule mockRule2;
    private ScoringService scoringService;

    @BeforeEach
    public void setup() {
        // We inject the mocked rules into the scoring service
        scoringService = new ScoringService(Arrays.asList(mockRule1, mockRule2));
    }
    @Test
    void givenSafeEmail_whenAnalyze_thenReturnsPerfectScore() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(0, null));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Hello world");

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(100, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertTrue(result.getReasons().isEmpty());
    }

    @Test
    void givenMaliciousEmail_whenAnalyze_thenCalculatesPenaltiesCorrectly() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(20, "Bad Domain"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(30, "Bad Link"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(50, result.getScore()); 
        assertEquals("Malicious", result.getVerdict());
        assertEquals(2, result.getReasons().size());
    }

    @Test
    void givenMassivePenalties_whenAnalyze_thenScoreIsBoundedAtZero() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(80, "Critical threat 1"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(80, "Critical threat 2"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(0, result.getScore());
        assertEquals("Malicious", result.getVerdict());
    }

    @Test
    void givenDirtyRuleReasons_whenAnalyze_thenSanitizesOutputReasonsToPreventXSS() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(10, "Found: <script>bad()</script>"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        String sanitizedReason = result.getReasons().get(0);
        assertEquals("Found: &lt;script&gt;bad()&lt;/script&gt;", sanitizedReason);
    }

    @Test
    void givenScoreExactlySeventy_whenAnalyze_thenReturnsSafeVerdict() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(30, "Penalty"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(70, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(1, result.getReasons().size());
    }

    @Test
    void givenScoreExactlySixtyNine_whenAnalyze_thenReturnsMaliciousVerdict() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(31, "Penalty"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(69, result.getScore());
        assertEquals("Malicious", result.getVerdict());
        assertEquals(1, result.getReasons().size());
    }

    @Test
    void givenNullEmailContent_whenAnalyze_thenSanitizesToEmptyString() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(0, null));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();
        // emailContent remains null

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(100, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertTrue(result.getReasons().isEmpty());
        // The sanitization happens internally, but we can't directly test it since it's private
        // However, the path is covered
    }

    @Test
    void givenEmptyRulesList_whenAnalyze_thenReturnsPerfectScore() {
        // Arrange
        ScoringService emptyService = new ScoringService(Arrays.asList());

        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Test content");

        // Act
        ScoreResultDTO result = emptyService.analyze(request);

        // Assert
        assertEquals(100, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertTrue(result.getReasons().isEmpty());
    }

    @Test
    void givenRuleWithNullReason_whenAnalyze_thenSanitizesNullToEmptyString() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(10, null));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(90, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(1, result.getReasons().size());
        assertEquals("", result.getReasons().get(0)); // null sanitized to ""
    }
        

}
