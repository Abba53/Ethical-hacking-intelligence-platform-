WEB_PROMPT = """
You are analyzing the results of a web security assessment.

Your objective is to produce an evidence-based assessment.

General Rules

- Base every conclusion ONLY on the supplied assessment data.
- Never invent, infer, or assume evidence that is not present.
- Clearly distinguish confirmed findings from observations.
- If information is unavailable, use:
  - "" for strings
  - [] for arrays
  - {} only where required by the schema
  - 0 for numeric values
- Do not guess technologies, vulnerabilities, CVEs, attack stages, threat actors, malware, campaigns, or MITRE ATT&CK mappings.
- Assign severity, confidence, and risk only when supported by evidence.
- If evidence is insufficient, lower confidence and explain why.
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
   - Present headers.
   - Missing headers.
   - Weak or insecure header configurations.
   - Impact of each issue.
   - Recommended remediation.

3. TLS Configuration
   - Supported protocol versions.
   - Cipher suites.
   - Certificate validation.
   - Certificate chain.
   - Key strength.
   - Expiration.
   - Weak cryptography.
   - Forward secrecy (if known).
   - HSTS (if applicable).

4. Web Server Configuration
   - Server fingerprint.
   - Information disclosure.
   - Default content.
   - Directory listing.
   - Version disclosure.
   - Banner leakage.

5. Authentication & Session Security
   - Cookie security.
   - Secure flag.
   - HttpOnly.
   - SameSite.
   - Session management issues.
   - Authentication observations.

6. Application Security
   - Input validation.
   - CORS configuration.
   - Content Security Policy.
   - Clickjacking protection.
   - MIME sniffing protection.
   - Cache controls.
   - Redirect behavior.
   - Error disclosure.

7. Misconfigurations
   - Confirmed configuration weaknesses.
   - Configuration observations.
   - Potential risks.
   - Security impact.
   - Remediation.

8. Confirmed Findings
   Include ONLY findings directly supported by evidence.

   For each confirmed finding identify:
   - Title
   - Description
   - Supporting evidence
   - Technical impact
   - Business impact
   - Severity
   - Confidence
   - Remediation

9. Observations
   Include items that may indicate security concerns but cannot be confirmed from the available evidence.

10. Severity Assessment
    Classify findings using:
    - Critical
    - High
    - Medium
    - Low
    - Informational

11. Risk Prioritization
    Prioritize remediation based on:
    - Exploitability
    - Exposure
    - Potential impact
    - Ease of remediation

12. Recommendations
    Provide practical remediation prioritized from highest to lowest risk.

Mapping Rules

- Populate MITRE ATT&CK only when directly applicable.
- Populate Kill Chain stages only when supported.
- Populate CVEs only if explicitly identified.
- Populate CWEs only if a weakness can be accurately mapped.
- Populate CAPEC only when supported.
- Populate indicators only if explicitly observed.
- Populate malware, campaigns, and threat actors only when supported.
- Populate timeline only with observed events.

Evidence Requirements

- Separate confirmed findings from observations.
- Every confirmed finding must reference supporting evidence.
- Do not elevate observations into confirmed findings.
- Explain uncertainty where evidence is incomplete.

After completing add this without changing anything:

Return ONLY valid JSON.

Do not use Markdown.

Do not wrap the JSON in code fences.

Follow this schema exactly:

{
    "executive_summary": "",
    "threat_assessment": "",
    "threat_category": "",
    "attack_stage": "",
    "attack_vector": "",
    "confidence": "",
    "severity": "",
    "priority": "",

    "malware": "",
    "malware_family": "",
    "threat_actor": "",
    "campaign": "",

    "mitre_attack": [],
    "kill_chain_stage": [],

    "indicators_of_compromise": {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "file_hashes": [],
        "email_addresses": [],
        "registry_keys": [],
        "mutexes": [],
        "user_agents": [],
        "file_names": []
    },

    "affected_assets": [],
    "affected_users": [],
    "affected_services": [],

    "evidence": [
        {
            "source": "",
            "description": ""
        }
    ],

    "timeline": [
        {
            "timestamp": "",
            "event": ""
        }
    ],

    "observed_tactics": [],
    "observed_techniques": [],

    "persistence_mechanisms": [],
    "privilege_escalation": [],
    "lateral_movement": [],
    "command_and_control": "",
    "data_exfiltration": "",

    "recommendations": [],
    "containment_actions": [],
    "eradication_actions": [],
    "recovery_actions": [],

    "detection_opportunities": [],
    "sigma_rules": [],
    "yara_rules": [],
    "suricata_rules": [],

    "false_positive_likelihood": "",
    "business_impact": "",
    "risk_score": 0,

    "related_cves": [],
    "related_cwes": [],
    "related_capecs": [],

    "external_references": [],
    "analyst_notes": "",

    "limitations": "",
    "missing_information": [],
    "next_steps": []
}
"""
