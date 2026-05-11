package com.emailscorer.upwind_home_assignment.controller;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;
import com.emailscorer.upwind_home_assignment.dto.ScoreResultDTO;
import com.emailscorer.upwind_home_assignment.service_layer.ScoringService;

import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class EmailScoringController {

    private final ScoringService scoringService;
     private static final Logger logger = LoggerFactory.getLogger(EmailScoringController.class);
    
    // we inject the expected API key from application properties
    @Value("${security.api.key:assignment-secret-key}")
    private String expectedApiKey;

    public EmailScoringController(ScoringService scoringService) {
        this.scoringService = scoringService;
    }
    @PostMapping("/score")
    public ResponseEntity<ScoreResultDTO> calculateScore(
            @RequestHeader(value = "X-API-KEY", required = false) String apiKey,
            @Valid @RequestBody ScoreRequestDTO request) {

        logger.info("Received email scoring request");

        // api key authentication
        if (!expectedApiKey.equals(apiKey)) {
            logger.warn("Unauthorized access attempt - invalid API key");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        ScoreResultDTO result = scoringService.analyze(request);
        logger.info("Email scoring completed successfully. Score: {}, Verdict: {}", result.getScore(), result.getVerdict());
        // We return the result as JSON, and the UI will handle rendering it safely.
        return ResponseEntity.ok(result);
    }
}

