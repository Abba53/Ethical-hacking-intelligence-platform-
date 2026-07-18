from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class AIResponse:

    success: bool

    provider: str

    report_type: str

    analysis: Any

    raw_response: str = ""

    error: str | None = None

    execution_time_ms: int = 0
