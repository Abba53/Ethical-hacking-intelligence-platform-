import json

from analysis.schema.recon_schema import RECON_SCHEMA

RECON_PROMPT = f"""
You are reviewing reconnaissance results from an authorized security assessment.

Your objective is to produce an evidence-based reconnaissance assessment without speculation.

Analyze the supplied evidence and identify:

- Executive Summary
- Attack Surface
    - Internet-facing assets
    - Public infrastructure
    - Domains
    - Subdomains
    - IP addresses
    - Cloud assets
    - APIs
    - Web applications
    - Services
    - Technologies
    - Certificates
    - DNS information
- Internet Exposure
    - Exposed services
    - Open ports
    - Public endpoints
    - Authentication surfaces
    - Administrative interfaces
    - Third-party exposure
- Interesting / Exposed Assets
    - High-value assets
    - Critical infrastructure
    - Administrative systems
    - Identity infrastructure
    - Developer assets
    - Storage services
    - Cloud resources
    - Email infrastructure
    - Network devices
- Possible Entry Points
    - Public-facing applications
    - Exposed services
    - Authentication endpoints
    - Remote access services
    - APIs
    - Misconfigurations directly supported by the evidence
- False Positives
    - Findings that are likely incorrect
    - Findings requiring manual validation
- Recommended Next Steps
    - Safe validation activities
    - Additional reconnaissance
    - Manual verification
    - Defensive recommendations
    - Prioritized follow-up actions

Strict requirements:

- Only reason from the supplied evidence.
- Never invent assets, services, vulnerabilities, technologies, attackers, campaigns, malware, or indicators.
- Never infer exploitability without explicit supporting evidence.
- Distinguish clearly between:
    - Observed facts
    - Evidence-supported inferences
    - Unknown or unavailable information
- If information is missing, use empty values or explicitly state that evidence is insufficient.
- If a field cannot be determined from the supplied evidence, return an empty string or empty array.
- Do not exaggerate risk.
- Do not assume vulnerabilities exist.
- Only populate structured fields when directly supported by the supplied evidence.
- Maintain internal consistency across all output fields.

Return ONLY valid JSON.

Do not use Markdown.

Do not wrap the JSON in code fences.

Follow this schema exactly:

{json.dumps(RECON_SCHEMA, indent=4)}
"""
