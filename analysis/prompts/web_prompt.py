import json

from analysis.schema.web_schema import WEB_SCHEMA

WEB_PROMPT = f"""
You are analyzing the results of a web security assessment.

Your objective is to produce an evidence-based assessment.

General Rules

- Base every conclusion ONLY on the supplied assessment data.
- Never invent, infer, or assume evidence that is not present.
- Clearly distinguish confirmed findings from observations.
- If information is unavailable, use "" for strings or [] for arrays.
- Do not guess technologies, vulnerabilities, or CVEs.
- Assign risk only when supported by evidence.
- If evidence is insufficient, explain why in the finding description.
- Every confirmed finding must include supporting evidence from the assessment.
- Do not duplicate findings.
- Do not contradict the supplied evidence.
- Keep all descriptions concise, factual, and technically accurate.

Analyze and explain:

1. Executive Summary
   - Overall security posture.
   - Most important security risks.
   - Overall exposure.

2. Security Headers
   - Present, missing, or weak headers and their impact.

3. TLS Configuration
   - Protocol versions, cipher suites, certificate validity, weak cryptography.

4. Web Server Configuration
   - Server fingerprint, information disclosure, version disclosure.

5. Authentication & Session Security
   - Cookie security, Secure flag, HttpOnly, SameSite, session issues.

6. Application Security
   - Input validation, CORS, CSP, clickjacking protection, MIME sniffing protection.

7. Misconfigurations
   - Confirmed configuration weaknesses and their security impact.

8. Findings
   Include ONLY findings directly supported by evidence. For each, capture
   what the issue is, why it matters, and how to remediate it.

9. Vulnerabilities
   Include only vulnerabilities directly supported by evidence, with
   enough detail to act on.

10. Risk
    Classify overall risk using: Critical / High / Medium / Low / Informational,
    based on exploitability, exposure, and potential impact.

11. Recommendations
    Provide practical remediation prioritized from highest to lowest risk.

Evidence Requirements

- Every finding must reference supporting evidence.
- Do not elevate unconfirmed observations into confirmed findings.
- Explain uncertainty where evidence is incomplete.

Return ONLY valid JSON.

Do not use Markdown.

Do not wrap the JSON in code fences.

Follow this schema exactly:

{json.dumps(WEB_SCHEMA, indent=4)}
"""
