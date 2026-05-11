package com.emailscorer.upwind_home_assignment.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
import com.emailscorer.upwind_home_assignment.dto.ScoreResultDTO;
import com.emailscorer.upwind_home_assignment.service_layer.ScoringService;

@ExtendWith(MockitoExtension.class)
public class ScoreControllerTest {
    @Mock
    private ScoringService scoringService;

    private EmailScoringController controller;

    @BeforeEach
    public void setup() {
        controller = new EmailScoringController(scoringService);
        // Set the expected API key using reflection
        ReflectionTestUtils.setField(controller, "expectedApiKey", "test-api-key");
    }

    // ==================== VALID API KEY TESTS ====================

    @Test
    void givenValidApiKey_whenCalculateScore_thenReturnsOkWithResult() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        ScoreResultDTO expectedResult = new ScoreResultDTO(85, "Safe", java.util.Arrays.asList("Minor issue"));
        when(scoringService.analyze(any(ScoreRequestDTO.class))).thenReturn(expectedResult);

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("test-api-key", request);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(expectedResult, response.getBody());
        verify(scoringService).analyze(request);
    }

    @Test
    void givenValidApiKey_whenCalculateScore_thenCallsServiceWithRequest() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("test@example.com");
        request.setEmailContent("Test content");
        ScoreResultDTO mockResult = new ScoreResultDTO(100, "Safe", java.util.Arrays.asList());
        when(scoringService.analyze(any(ScoreRequestDTO.class))).thenReturn(mockResult);

        // Act
        controller.calculateScore("test-api-key", request);

        // Assert
        verify(scoringService).analyze(request);
    }

    // ==================== INVALID API KEY TESTS ====================

    @Test
    void givenInvalidApiKey_whenCalculateScore_thenReturnsUnauthorized() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("wrong-api-key", request);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(null, response.getBody());
        verify(scoringService, never()).analyze(any(ScoreRequestDTO.class));
    }

    @Test
    void givenNullApiKey_whenCalculateScore_thenReturnsUnauthorized() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore(null, request);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(null, response.getBody());
        verify(scoringService, never()).analyze(any(ScoreRequestDTO.class));
    }

    @Test
    void givenEmptyApiKey_whenCalculateScore_thenReturnsUnauthorized() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("", request);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(null, response.getBody());
        verify(scoringService, never()).analyze(any(ScoreRequestDTO.class));
    }

    @Test
    void givenCaseSensitiveApiKeyMismatch_whenCalculateScore_thenReturnsUnauthorized() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("TEST-API-KEY", request);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(null, response.getBody());
        verify(scoringService, never()).analyze(any(ScoreRequestDTO.class));
    }

    // ==================== SERVICE RESULT VARIATIONS ====================

    @Test
    void givenValidApiKeyAndMaliciousResult_whenCalculateScore_thenReturnsMaliciousResult() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        ScoreResultDTO maliciousResult = new ScoreResultDTO(30, "Malicious", java.util.Arrays.asList("Suspicious link", "Bad sender"));
        when(scoringService.analyze(any(ScoreRequestDTO.class))).thenReturn(maliciousResult);

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("test-api-key", request);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(30, response.getBody().getScore());
        assertEquals("Malicious", response.getBody().getVerdict());
        assertEquals(2, response.getBody().getReasons().size());
    }

    @Test
    void givenValidApiKeyAndSafeResult_whenCalculateScore_thenReturnsSafeResult() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        ScoreResultDTO safeResult = new ScoreResultDTO(95, "Safe", java.util.Arrays.asList());
        when(scoringService.analyze(any(ScoreRequestDTO.class))).thenReturn(safeResult);

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("test-api-key", request);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(95, response.getBody().getScore());
        assertEquals("Safe", response.getBody().getVerdict());
        assertEquals(0, response.getBody().getReasons().size());
    }

    // ==================== EDGE CASES ====================

    @Test
    void givenValidApiKeyAndNullRequest_whenCalculateScore_thenCallsServiceWithNull() {
        // Arrange - Note: In real usage, @Valid would prevent null, but testing the method directly
        ScoreResultDTO mockResult = new ScoreResultDTO(100, "Safe", java.util.Arrays.asList());
        when(scoringService.analyze(null)).thenReturn(mockResult);

        // Act
        ResponseEntity<ScoreResultDTO> response = controller.calculateScore("test-api-key", null);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(scoringService).analyze(null);
    }
}
