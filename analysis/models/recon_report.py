from dataclasses import dataclass, field


@dataclass(slots=True)
class ReconReport:

    executive_summary: str = ""

    attack_surface: str = ""

    exposed_assets: list[str] = field(default_factory=list)

    entry_points: list[str] = field(default_factory=list)

    false_positives: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)
