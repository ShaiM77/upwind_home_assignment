package com.emailscorer.upwind_home_assignment.dto;

import java.util.List;

public class ScoreResultDTO {
    private int score;
    private String verdict;
    private List<String> reasons;

    public ScoreResultDTO(int score, String verdict, List<String> reasons) {
        this.score = score;
        this.verdict = verdict;
        this.reasons = reasons;
    }
    public int getScore() { 
        return score; }

    public String getVerdict() { 
        return verdict; }

    public List<String> getReasons() { 
        return reasons; }
}
