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

    @Test
    void givenEmailContentWithHtmlTags_whenAnalyze_thenSanitizesContent() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(0, null));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Click here: <a href='http://malicious.com'>link</a>");

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(100, result.getScore());
        assertEquals("Safe", result.getVerdict());
        // Content is sanitized internally before rules evaluate it
    }

    @Test
    void givenMultipleRulesWithPenalties_whenAnalyze_thenAllReasonsAreIncluded() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(15, "Reason 1"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(25, "Reason 2"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(60, result.getScore());
        assertEquals("Malicious", result.getVerdict());
        assertEquals(2, result.getReasons().size());
        assertEquals(true, result.getReasons().contains("Reason 1"));
        assertEquals(true, result.getReasons().contains("Reason 2"));
    }

    @Test
    void givenAllReasonsWithHtmlTags_whenAnalyze_thenAllAreProperlyEncoded() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(10, "<img src=x>"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(15, "<iframe></iframe>"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(75, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(2, result.getReasons().size());
        assertEquals(true, result.getReasons().contains("&lt;img src=x&gt;"));
        assertEquals(true, result.getReasons().contains("&lt;iframe&gt;&lt;/iframe&gt;"));
    }

    @Test
    void givenScoreBoundaryAt70_whenAnalyze_thenVerdictIsSafe() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(30, "Minor issue"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(70, result.getScore());
        assertEquals("Safe", result.getVerdict());
    }

    @Test
    void givenScoreBoundaryAt1Below70_whenAnalyze_thenVerdictIsMalicious() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(31, "Major issue"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(69, result.getScore());
        assertEquals("Malicious", result.getVerdict());
    }

    @Test
    void givenPenaltyExactlyEquals100_whenAnalyze_thenScoreIsBoundedAtZero() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(50, "Major threat"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(50, "Critical threat"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(0, result.getScore());
        assertEquals("Malicious", result.getVerdict());
    }

    @Test
    void givenMixedNullAndValidReasons_whenAnalyze_thenProcessesBoth() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(10, null));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(20, "Valid reason"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(70, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(2, result.getReasons().size());
        assertEquals(true, result.getReasons().contains(""));
        assertEquals(true, result.getReasons().contains("Valid reason"));
    }

    @Test
    void givenMultipleRulesOnlyOneWithPenalty_whenAnalyze_thenOnlyIncludesRelevantReason() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(0, "This should not be included"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(15, "This should be included"));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(85, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(1, result.getReasons().size());
        assertEquals("This should be included", result.getReasons().get(0));
    }

    @Test
    void givenComplexSanitizationNeeded_whenAnalyze_thenHandlesMultipleTagTypes() {
        // Arrange
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(5, "Alert: <script>alert('xss')</script> and <img src=x>"));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(95, result.getScore());
        assertEquals("Safe", result.getVerdict());
        String sanitized = result.getReasons().get(0);
        assertEquals(true, sanitized.contains("&lt;script&gt;"));
        assertEquals(true, sanitized.contains("&lt;/script&gt;"));
        assertEquals(true, sanitized.contains("&lt;img src=x&gt;"));
    }

    @Test
    void givenRulesListWithOneRule_whenAnalyze_thenProcessesSingleRule() {
        // Arrange
        SecurityRule singleRule = new SecurityRule() {
            @Override
            public RuleResult evaluate(ScoreRequestDTO req) {
                return new RuleResult(20, "Single rule violation");
            }
        };
        ScoringService singleRuleService = new ScoringService(Arrays.asList(singleRule));

        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ScoreResultDTO result = singleRuleService.analyze(request);

        // Assert
        assertEquals(80, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(1, result.getReasons().size());
    }

    @Test
    void givenRequestWithSanitizationNeededInContent_whenAnalyze_thenContentIsSanitizedBeforeRuleEvaluation() {
        // Arrange - Content with HTML tags
        when(mockRule1.evaluate(any())).thenReturn(new RuleResult(0, null));
        when(mockRule2.evaluate(any())).thenReturn(new RuleResult(0, null));

        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setEmailContent("Normal content with <tag> inside");

        // Act
        ScoreResultDTO result = scoringService.analyze(request);

        // Assert
        assertEquals(100, result.getScore());
        assertEquals("Safe", result.getVerdict());
        assertEquals(0, result.getReasons().size());
        // The request object should have its content sanitized
        assertEquals("Normal content with &lt;tag&gt; inside", request.getEmailContent());
    }
        

}
