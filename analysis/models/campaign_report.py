from dataclasses import dataclass, field


@dataclass(slots=True)
class CampaignReport:

    executive_summary: str = ""

    campaign_assessment: str = ""

    campaign_name: str = ""

    threat_actors: list[str] = field(default_factory=list)

    malware: list[str] = field(default_factory=list)

    infrastructure: list[str] = field(default_factory=list)

    targeted_sectors: list[str] = field(default_factory=list)

    targeted_regions: list[str] = field(default_factory=list)

    attack_stages: list[str] = field(default_factory=list)

    mitre_attack: list[str] = field(default_factory=list)

    indicators: list[str] = field(default_factory=list)

    confidence: str = ""

    risk: str = ""

    recommendations: list[str] = field(default_factory=list)

    detection_opportunities: list[str] = field(default_factory=list)
