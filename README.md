# Upwind Home Assignment: Suspicious Email Scorer

## Overview
This project is a backend threat-analysis engine designed to evaluate raw email data and detect potential phishing, spoofing, and malware delivery attempts. 

Built with **Java** and **Spring Boot**, the engine exposes a secure REST API that accepts email metadata and content, processes it through a highly extensible rules engine, and returns a cumulative risk score alongside sanitized, explanations.

## Architecture & Flow
1. **Client Layer:** A Google Workspace (Gmail) Add-on extracts real-time email context (Headers, Body, Attachment Names) without downloading heavy binary payloads.
2. **Transport Layer:** The payload is sent securely via HTTPS to the backend API (tunneled via ngrok for local development).
3. **Controller Layer:** The `EmailScoringController` authenticates the request via an API Key and enforces strict payload size limits to prevent Denial of Service (DoS) attacks.
4. **Service & Rules Engine:** The `ScoringService` iterates over a dynamically injected list of `SecurityRule` components. Each rule evaluates a specific threat vector independently.
5. **Response:** Penalties are aggregated, bounded at 0, and the explanation strings are strictly sanitized to prevent Cross-Site Scripting (XSS) before being returned to the UI.

## Implemented Security Rules
The engine utilizes a Strategy Pattern, making it trivial to add new detection capabilities. Current rules include:
* **`DangerousAttachmentRule`**: Scans attachment names for critical executables (`.exe`, `.scr`, `.bat`) and high-risk archives (`.zip`, `.iso`), applying cumulative penalties per file.
* **`SuspiciousLinkRule`**: Extracts and evaluates URLs from the email body against a mapped matrix of known malicious/anonymous TLDs (e.g., `.top`, `.xyz`). Utilizes memory-sets to prevent double-penalization of identical links.
* **`SuspiciousSenderTldRule`**: Evaluates the originating domain of the sender against the high-risk TLD matrix.
* **`ReplyToMismatchRule`**: Detects spoofing attempts by comparing the `Sender` header against the `Reply-To` header, stripping angle brackets and normalizing cases for accurate comparison.
* **`PhishingTermsRule`**: Scans the email body for common social engineering phrases (e.g., "urgent", "verify your account"). Applies a minor, cumulative penalty per occurrence to act as a risk modifier—minimizing false positives for normal emails while heavily penalizing keyword-stuffed scams.

## Security & Design Decisions
* **XSS Prevention:** The engine sanitizes all output reasons (e.g., escaping `<` and `>`) to ensure the downstream UI cannot be compromised by malicious HTML/JS embedded in the email body.
* **Permissive Format vs. Strict Size:** The DTO intentionally omits `@NotBlank` constraints on the email body to allow the engine to evaluate empty emails carrying malicious attachments (a common threat vector). However, it enforces strict `@Size(max = 50000)` constraints to protect the JVM from memory exhaustion and algorithmic complexity attacks.
* **Authentication:** All endpoints require an `X-API-KEY` header, rejecting unauthorized requests with a `401 Unauthorized` status.

## Testing Strategy
This project demonstrates complete confidence through a robust Testing Pyramid:
1. **Unit Tests (JUnit 5 + Mockito):** * Exhaustive edge-case testing for every individual `SecurityRule` (case insensitivity, null handling, cumulative math).
   * Service-layer testing utilizing `@Mock` rules to ensure proper aggregation and bounding logic.
2. **Controller Tests (`@WebMvcTest`):**
   * Validates the web contract, ensuring Spring Boot correctly handles missing API keys, oversized payloads, and JSON serialization.
3. **Acceptance Tests (`MockMvc`):**
   * End-to-end integration testing simulating live JSON payloads hitting the API to verify the entire Spring Application Context and wiring.

## Setup & Running Instructions

### Prerequisites
* Java 17 or higher
* Maven
* (Optional) VS Code with the "REST Client" extension for API simulation.

### Running the Application
1. Clone the repository.
2. Build the project:
   ```bash
   mvn clean install
