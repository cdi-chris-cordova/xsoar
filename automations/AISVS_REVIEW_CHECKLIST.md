# AISVS Review Checklist for Xsoar-Automations

Use this checklist for implementation and review work in this repository.

This repo currently contains a non-AI XSOAR automation, so AISVS applies mainly to the security properties of the automation itself:
input validation, secrets handling, deployment/configuration, and logging.

For any future AI, LLM, embedding, vector store, or agent functionality, extend the review to the AISVS AI-specific chapters below.

Also review applicable OWASP Top 10:2025 risks for any web-facing surfaces, supporting APIs, authentication flows, configuration, and error handling.

## Review Baseline

- [ ] State the AISVS version used for the review (`v1.0` unless the project adopts a newer version).
- [ ] State the OWASP Top 10 version used for the review (`2025` unless the project adopts a newer version).
- [ ] Identify whether the change touches AI/LLM/model, vector, prompt, or agentic behavior.
- [ ] Identify whether the change touches a web-facing surface, integration endpoint, auth flow, or external API.
- [ ] Mark chapters as applicable or not applicable, with a short reason.
- [ ] Record evidence for verification: tests, code references, logs, screenshots, or policy checks.

## Current Repo Mapping

For the current script, the primary AISVS focus is:

- `C2` Input Validation
- `C4` Infrastructure, Configuration & Deployment Security
- `C5` Access Control & Identity for AI Components & Users
- `C12` Monitoring, Logging & Anomaly Detection

For the current script, the primary OWASP Top 10:2025 focus is:

- `A01` Broken Access Control
- `A02` Security Misconfiguration
- `A03` Software Supply Chain Failures
- `A04` Cryptographic Failures
- `A05` Injection
- `A07` Authentication Failures
- `A08` Software or Data Integrity Failures
- `A09` Security Logging and Alerting Failures
- `A10` Mishandling of Exceptional Conditions

If AI functionality is added later, also review:

- `C1` Training Data Integrity & Traceability
- `C3` Model Lifecycle Management & Change Control
- `C6` Supply Chain Security for Models
- `C7` Model Behavior, Output Control & Safety Assurance
- `C8` Memory, Embeddings & Vector Database Security
- `C9` Orchestration & Agentic Security
- `C10` Model Context Protocol (MCP) Security
- `C11` Adversarial Robustness

## Checklist

### C2 Input Validation

- [ ] Treat all external inputs as untrusted.
- [ ] Validate script arguments before use.
- [ ] Validate API responses before parsing or storing them.
- [ ] Handle missing, malformed, or unexpected fields safely.
- [ ] Fail closed on unexpected types or empty responses when the workflow depends on them.

### C4 Infrastructure, Configuration & Deployment Security

- [ ] No secrets are hardcoded in source.
- [ ] Sensitive values are supplied through XSOAR sensitive args or vault-backed credentials.
- [ ] Outbound requests use explicit TLS endpoints and timeouts.
- [ ] Dependencies are minimal and approved.
- [ ] Deployment-specific values are configurable without code edits.
- [ ] Errors are handled explicitly instead of being ignored.

### C5 Access Control & Identity for AI Components & Users

- [ ] Each credential has a clear owner or service account.
- [ ] Credentials are scoped to the minimum access required.
- [ ] Secrets are not logged, echoed, or stored in context.
- [ ] Credential rotation is supported operationally.
- [ ] If AI components are added later, they use identities distinct from human users.

### C12 Monitoring, Logging & Anomaly Detection

- [ ] Security-relevant actions are observable.
- [ ] Failure states are surfaced clearly for operators.
- [ ] Logs do not leak credentials, tokens, prompts, or sensitive payloads.
- [ ] Alerts or detections exist for unexpected behavior changes.
- [ ] If AI features are added later, monitor for injection, abnormal tool use, and output drift.

## OWASP Top 10:2025 Checklist

### A01 Broken Access Control

- [ ] The automation only accesses the data and systems it is allowed to access.
- [ ] Any external API calls use least-privilege credentials.
- [ ] No data is exposed to unauthorized users through context, outputs, or logs.

### A02 Security Misconfiguration

- [ ] Endpoints, timeouts, headers, and TLS behavior are explicit.
- [ ] Production settings are not embedded as hardcoded assumptions.
- [ ] Unsafe defaults are not relied on.

### A03 Software Supply Chain Failures

- [ ] Third-party libraries are minimized and tracked.
- [ ] Changes to dependencies are reviewed before rollout.
- [ ] No unverified code, snippets, or artifacts are introduced.

### A04 Cryptographic Failures

- [ ] Secrets are stored and handled securely.
- [ ] Sensitive data is transmitted only over protected channels.
- [ ] No weak or ad hoc crypto is introduced.

### A05 Injection

- [ ] Inputs are validated before being used in commands, queries, or API calls.
- [ ] Untrusted values are not concatenated into shell commands, queries, or prompts without controls.
- [ ] Output encoding or escaping is used where needed.

### A06 Insecure Design

- [ ] The workflow has explicit security requirements before implementation.
- [ ] Security decisions are designed in rather than patched in after the fact.
- [ ] High-risk behaviors require deliberate operator approval or another control.

### A07 Authentication Failures

- [ ] Authentication secrets are never hardcoded.
- [ ] Credential rotation is operationally supported.
- [ ] Auth failures are handled without leaking sensitive information.

### A08 Software or Data Integrity Failures

- [ ] API responses are validated before use.
- [ ] Stored records are checked for type and schema before comparison or write-back.
- [ ] Data that influences behavior is trusted only after validation.

### A09 Security Logging and Alerting Failures

- [ ] Security-relevant failures are visible to operators.
- [ ] Logs and context do not leak secrets.
- [ ] Unexpected states produce actionable output.

### A10 Mishandling of Exceptional Conditions

- [ ] Missing, malformed, and partial data are handled explicitly.
- [ ] Timeouts and request failures are not ignored.
- [ ] The automation fails closed when required data cannot be trusted.

## If AI, LLM, or Agent Features Are Introduced

### C1 Training Data Integrity & Traceability

- [ ] Data provenance is documented.
- [ ] Training or fine-tuning datasets are versioned.
- [ ] Data poisoning risks are considered.

### C3 Model Lifecycle Management & Change Control

- [ ] Model versions are pinned and reviewed.
- [ ] Promotion, rollback, and retirement are controlled.
- [ ] Model changes are traceable to a change request or release.

### C6 Supply Chain Security for Models

- [ ] Model artifacts and dependencies come from verified sources.
- [ ] Third-party model and prompt dependencies are reviewed before use.
- [ ] Integrity checks or signatures are used where feasible.

### C7 Model Behavior, Output Control & Safety Assurance

- [ ] Model output is validated before triggering side effects.
- [ ] High-impact actions require human confirmation.
- [ ] Unsafe or out-of-policy outputs are blocked or contained.

### C8 Memory, Embeddings & Vector Database Security

- [ ] Stored memory is scoped and access-controlled.
- [ ] Sensitive data retention is minimized.
- [ ] Retrieval boundaries prevent cross-tenant or cross-user leakage.

### C9 Orchestration & Agentic Security

- [ ] Tool boundaries are explicit and least-privilege.
- [ ] Prompt injection and tool injection are addressed.
- [ ] Autonomous actions are bounded by policy and approval.

### C10 Model Context Protocol (MCP) Security

- [ ] MCP servers and tools are authenticated and authorized.
- [ ] Tool schemas are narrow and do not expose unnecessary capabilities.
- [ ] Transport and trust boundaries are documented.

### C11 Adversarial Robustness

- [ ] The system is tested against malicious and evasive inputs.
- [ ] Rate limits and abuse detection are in place.
- [ ] There is a safe fallback when the model is uncertain or attacked.

## Review Output Template

- AISVS version:
- Applicable chapters:
- Non-applicable chapters and why:
- Evidence reviewed:
- Residual risks:
- Follow-up actions:
