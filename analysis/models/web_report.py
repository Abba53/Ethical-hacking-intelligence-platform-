from dataclasses import dataclass, field


@dataclass(slots=True)
class WebReport:

    executive_summary: str = ""

    findings: list[str] = field(default_factory=list)

    vulnerabilities: list[str] = field(default_factory=list)

    misconfigurations: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)

    risk: str = ""

