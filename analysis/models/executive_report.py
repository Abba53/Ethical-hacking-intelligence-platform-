from dataclasses import dataclass, field


@dataclass(slots=True)
class ExecutiveReport:

    summary: str = ""

    business_impact: str = ""

    technical_impact: str = ""

    overall_risk: str = ""

    priorities: list[str] = field(default_factory=list)

    next_actions: list[str] = field(default_factory=list)
