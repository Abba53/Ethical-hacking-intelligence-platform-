from dataclasses import dataclass, field


@dataclass(slots=True)
class ThreatReport:

    executive_summary: str = ""

    threat_assessment: str = ""

    attack_stage: str = ""

    confidence: str = ""

    malware: str = ""

    threat_actor: str = ""

    mitre_attack: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)

    detection_opportunities: list[str] = field(default_factory=list)

    priority: str = ""
