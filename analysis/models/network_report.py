from dataclasses import dataclass, field


@dataclass(slots=True)
class NetworkReport:

    reputation: str = ""

    risk: str = ""

    infrastructure: str = ""

    abuse_history: str = ""

    observations: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)
