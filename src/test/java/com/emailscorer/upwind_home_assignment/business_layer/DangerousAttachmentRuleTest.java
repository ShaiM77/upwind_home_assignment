package com.emailscorer.upwind_home_assignment.business_layer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.emailscorer.upwind_home_assignment.dto.ScoreRequestDTO;

public class DangerousAttachmentRuleTest {
    private DangerousAttachmentRule rule;

    @BeforeEach
    public void setup() {
        rule = new DangerousAttachmentRule();
    }

    // NULL/EMPTY attachment tests 

    @Test
    void givenNullAttachments_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(null);

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenEmptyAttachmentList_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(new ArrayList<>());

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    // SAFE attachment tests 

    @Test
    void givenSafeDocumentAttachment_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("document.pdf", "spreadsheet.xlsx"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenSafeTextFile_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("readme.txt", "notes.doc"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    //CRITICAL EXTENSION tests 40 penalty for each

    @Test
    void givenCriticalAttachmentExe_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("malware.exe"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".exe"));
        assertEquals(true, result.getReason().contains("CRITICAL"));
    }

    @Test
    void givenCriticalAttachmentScr_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("screen.scr"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".scr"));
    }

    @Test
    void givenCriticalAttachmentVbs_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("script.vbs"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".vbs"));
    }

    @Test
    void givenCriticalAttachmentBat_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("batch.bat"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".bat"));
    }

    @Test
    void givenCriticalAttachmentJs_whenEvaluate_thenReturnsCriticalPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("exploit.js"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".js"));
    }

    // HIGH-RISK extensions tests 25 pentalty for each

    @Test
    void givenHighRiskAttachmentZip_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("archive.zip"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".zip"));
        assertEquals(true, result.getReason().contains("HIGH RISK"));
    }

    @Test
    void givenHighRiskAttachmentRar_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("compressed.rar"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".rar"));
    }

    @Test
    void givenHighRiskAttachmentIso_whenEvaluate_thenReturnsHighPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("disk.iso"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains(".iso"));
    }

    // case insensitivity tests

    @Test
    void givenCriticalAttachmentUppercase_whenEvaluate_thenDetectsExtension() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("VIRUS.EXE"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenHighRiskAttachmentMixedCase_whenEvaluate_thenDetectsExtension() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("Archive.ZIP"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(25, result.getPenalty());
        assertNotNull(result.getReason());
    }

    // multiple attachments tests

    @Test
    void givenMultipleCriticalAttachments_whenEvaluate_thenCumulatesPenalties() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("virus.exe", "trojan.scr"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(80, result.getPenalty()); // 40 + 40
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("virus.exe"));
        assertEquals(true, result.getReason().contains("trojan.scr"));
    }

    @Test
    void givenMultipleHighRiskAttachments_whenEvaluate_thenCumulatesPenalties() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("file1.zip", "file2.rar", "file3.iso"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(75, result.getPenalty()); // 25 + 25 + 25
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("file1.zip"));
        assertEquals(true, result.getReason().contains("file2.rar"));
        assertEquals(true, result.getReason().contains("file3.iso"));
    }

    @Test
    void givenMixedCriticalAndHighRiskAttachments_whenEvaluate_thenCumulatesPenalties() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("virus.exe", "archive.zip"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(65, result.getPenalty()); // 40 + 25
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("virus.exe"));
        assertEquals(true, result.getReason().contains("archive.zip"));
    }

    // mixed safe and dangerous attachments tests

    @Test
    void givenMixedSafeAndDangerousAttachments_whenEvaluate_thenOnlyPenalizesDangerous() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("document.pdf", "virus.bat", "notes.txt"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("virus.bat"));
        assertEquals(false, result.getReason().contains("document.pdf"));
        assertEquals(false, result.getReason().contains("notes.txt"));
    }

    @Test
    void givenMultipleSafeWithOneCritical_whenEvaluate_thenDetectsCritical() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("readme.txt", "report.docx", "malware.exe", "image.png"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
        assertEquals(true, result.getReason().contains("malware.exe"));
    }

    // message formatting tests

    @Test
    void givenDangerousAttachment_whenEvaluate_thenReasonContainsFileName() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("suspicious_file.vbs"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        String reason = result.getReason();
        assertEquals(true, reason.contains("suspicious_file.vbs"));
        assertEquals(true, reason.contains("•"));
        assertEquals(true, reason.contains("Attachment"));
    }

    @Test
    void givenMultipleDangerousAttachments_whenEvaluate_thenReasonIncludesAllFileNames() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("first.exe", "second.zip", "third.bat"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        String reason = result.getReason();
        assertEquals(true, reason.contains("first.exe"));
        assertEquals(true, reason.contains("second.zip"));
        assertEquals(true, reason.contains("third.bat"));
    }

    // edge cases

    @Test
    void givenAttachmentWithMultipleDots_whenEvaluate_thenUsesLastExtension() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("document.backup.exe"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty());
        assertNotNull(result.getReason());
    }

    @Test
    void givenAttachmentWithoutExtension_whenEvaluate_thenReturnsNoPenalty() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("README"));

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenAttachmentWithPartialMatch_whenEvaluate_thenOnlyMatchesFullExtension() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("myexecutable.txt")); // contains "exe" but not ".exe"

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(0, result.getPenalty());
        assertEquals(null, result.getReason());
    }

    @Test
    void givenSingleAttachmentWithAllRiskyExtensionsInName_whenEvaluate_thenCountsOnce() {
        // Arrange
        ScoreRequestDTO request = new ScoreRequestDTO();
        request.setAttachmentNames(Arrays.asList("archive.exe")); // Only ends with .exe

        // Act
        RuleResult result = rule.evaluate(request);

        // Assert
        assertEquals(40, result.getPenalty()); // Should only count critical penalty once
        assertNotNull(result.getReason());
    }
}
