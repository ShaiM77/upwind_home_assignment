package com.emailscorer.upwind_home_assignment.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
import com.emailscorer.upwind_home_assignment.dto.ScoreResultDTO;
import com.emailscorer.upwind_home_assignment.service_layer.ScoringService;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(EmailScoringController.class)
public class ScoreControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ScoringService scoringService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void givenValidApiKey_whenCalculateScore_thenReturnsOkWithResult() throws Exception {
        // Arrange
        ScoreResultDTO expectedResult = new ScoreResultDTO(85, "Safe", Collections.singletonList("Minor issue"));
        when(scoringService.analyze(any(ScoreRequestDTO.class))).thenReturn(expectedResult);

        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setSender("test@example.com");

        // Act & Assert
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "assignment-secret-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(85))
                .andExpect(jsonPath("$.verdict").value("Safe"));
    }

    @Test
    void givenInvalidApiKey_whenCalculateScore_thenReturnsUnauthorized() throws Exception {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act & Assert
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "wrong-api-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void givenMissingApiKey_whenCalculateScore_thenReturnsUnauthorized() throws Exception {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();

        // Act & Assert
        mockMvc.perform(post("/api/score")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void givenMalformedJson_whenCalculateScore_thenReturnsBadRequest() throws Exception {
        // Arrange: Malformed JSON
        String malformedJson = "{\"emailContent\": \"test\", "; // Truncated JSON

        // Act & Assert
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "assignment-secret-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(malformedJson))
                .andExpect(status().isBadRequest());
    }
}
