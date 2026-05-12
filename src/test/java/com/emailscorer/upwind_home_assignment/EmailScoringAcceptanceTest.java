package com.emailscorer.upwind_home_assignment;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
public class EmailScoringAcceptanceTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;
    @Test
    void givenCompletelySafeEmail_whenSystemAnalyzes_thenReturnsPerfectScore() throws Exception {
        // Arrange: A perfectly normal, safe email
        ScoreRequestDTO safeRequest = new ScoreRequestDTO();
        safeRequest.setSender("boss@company.com");
        safeRequest.setReplyTo("boss@company.com");
        safeRequest.setEmailContent("Hey, are we still on for the meeting at 3?");
        safeRequest.setAttachmentNames(Arrays.asList("meeting_agenda.pdf"));
        safeRequest.setDmarcFailed(false);

        // Act & Assert: Send it through the entire booted system
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "assignment-secret-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(safeRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(100))
                .andExpect(jsonPath("$.verdict").value("Safe"))
                .andExpect(jsonPath("$.reasons").isEmpty());
    }

    @Test
    void givenUltimateScamEmail_whenSystemAnalyzes_thenReturnsZeroScoreAndMultipleReasons() throws Exception {
        // Arrange: The worst email ever written
        ScoreRequestDTO scamRequest = new ScoreRequestDTO();
        scamRequest.setSender("attacker@evil.zip"); // Critical TLD Penalty
        scamRequest.setReplyTo("different@phishing.com"); // Mismatch Penalty
        scamRequest.setEmailContent("URGENT: Verify your bank password here: http://malware.top"); // Link & Term Penalties
        scamRequest.setAttachmentNames(Arrays.asList("virus.exe")); // Critical Attachment Penalty
        scamRequest.setDmarcFailed(true); // Critical DMARC Penalty
        // Act & Assert: Ensure the system catches everything and bounds the score at 0
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "assignment-secret-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(scamRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(0))
                .andExpect(jsonPath("$.verdict").value("Malicious"))
                // We don't check the exact array size because rules might expand, 
                // but we verify that reasons were generated
                .andExpect(jsonPath("$.reasons").isNotEmpty()); 
    }
     @Test
    void givenOnlyDmarcFails_whenSystemAnalyzes_thenReturnsPenalty() throws Exception {
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setSender("user@company.com");
        dto.setReplyTo("user@company.com");
        dto.setEmailContent("Normal content");
        dto.setDmarcFailed(true);
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "assignment-secret-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.lessThan(100)))
                .andExpect(jsonPath("$.reasons").isNotEmpty());
    }

    @Test
    void givenOnlyDangerousAttachment_whenSystemAnalyzes_thenReturnsPenalty() throws Exception {
        ScoreRequestDTO dto = new ScoreRequestDTO();
        dto.setSender("user@company.com");
        dto.setReplyTo("user@company.com");
        dto.setEmailContent("Normal content");
        dto.setAttachmentNames(Arrays.asList("virus.exe"));
        mockMvc.perform(post("/api/score")
                .header("X-API-KEY", "assignment-secret-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.lessThan(100)))
                .andExpect(jsonPath("$.reasons").isNotEmpty());
    }

}
