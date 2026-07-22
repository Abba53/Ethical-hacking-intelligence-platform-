from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class WorkflowResult:
    success: bool
    workflow: str
    message: str = ""

    data: dict[str, Any] = field(default_factory=dict)

    errors: list[str] = field(default_factory=list)

    started_at: datetime | None = None

    finished_at: datetime | None = None

    duration_ms: float | None = None


class BaseWorkflow(ABC):
    """
    Base class for every workflow in the platform.
    """

    workflow_name = "base"

    async def run(self, *args, **kwargs) -> WorkflowResult:

        start = datetime.now(timezone.utc)

        try:

            result = await self.execute(*args, **kwargs)

            end = datetime.now(timezone.utc)

            result.started_at = start

            result.finished_at = end

            result.duration_ms = (
                end - start
            ).total_seconds() * 1000

            return result

        except Exception as exc:

            end = datetime.now(timezone.utc)

            return WorkflowResult(
                success=False,
                workflow=self.workflow_name,
                message="Workflow failed.",
                errors=[str(exc)],
                started_at=start,
                finished_at=end,
                duration_ms=(end - start).total_seconds() * 1000,
            )

    @abstractmethod
    async def execute(self, *args, **kwargs) -> WorkflowResult:
        """
        Child workflows implement this.
        """
        raise NotImplementedError
