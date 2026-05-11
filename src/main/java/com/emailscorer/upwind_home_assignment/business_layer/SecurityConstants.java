package com.emailscorer.upwind_home_assignment.business_layer;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SecurityConstants {
    public enum RiskLevel {
        CRITICAL(40, "Extreme risk: TLD mimics file extensions (deceptive link tactic)."),
        HIGH(25, "High risk: TLD is a known haven for free/anonymous malicious registrations."),
        MEDIUM(15, "Medium risk: TLD is frequently used for low-quality spam or niche phishing.");
        public final int penalty;
        public final String description;

        RiskLevel(int penalty, String description) {
            this.penalty = penalty;
            this.description = description;
        }
    }
    public static final Map<String, RiskLevel> TLD_RISK_MAP = new HashMap<>();
    static {
        // file extension mimicry used to creating deceptive links - CRITICAL
        TLD_RISK_MAP.put(".zip", RiskLevel.CRITICAL);
        TLD_RISK_MAP.put(".mov", RiskLevel.CRITICAL);

        // freenom / Free registration abuse for scams - HIGH
        for (String tld : Arrays.asList(".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu")) {
            TLD_RISK_MAP.put(tld, RiskLevel.HIGH);
        }

        // niche linking for phishing links or marketing spam - MEDIUM
        for (String tld : Arrays.asList(".loan", ".faith", ".accountant", ".racing", ".cricket", ".men", ".stream", ".online")) {
            TLD_RISK_MAP.put(tld, RiskLevel.MEDIUM);
        }
    }
    private SecurityConstants() {}
}
