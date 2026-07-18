from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from analysis.models.ai_response import AIResponse


class BaseAIProvider(ABC):
    """
    Abstract base class for all AI providers.

    Every provider must implement the same interface to ensure
    consistent behavior throughout the platform.
    """

    provider_name: str = "base"
    model_name: str = "unknown"
    supports_streaming: bool = False
    supports_images: bool = False
    supports_tools: bool = False

    def __str__(self) -> str:
        return f"{self.provider_name}:{self.model_name}"

    @abstractmethod
    async def analyze(
        self,
        prompt: str,
        **kwargs: Any,
    ) -> AIResponse:
        """
        Analyze a prompt and return a normalized AIResponse.
        """
        raise NotImplementedError

    async def health_check(self) -> bool:
        """
        Verify the provider is reachable.

        Override if the provider supports a health endpoint.
        """
        return True

    async def initialize(self) -> None:
        """
        Initialize resources such as HTTP clients,
        authentication, or model loading.
        """
        return None

    async def close(self) -> None:
        """
        Clean up resources.

        Override when using persistent HTTP sessions
        or other network resources.
        """
        return None

    def validate_prompt(self, prompt: str) -> None:
        """
        Validate prompt before sending it.
        """

        if not isinstance(prompt, str):
            raise TypeError("Prompt must be a string.")

        prompt = prompt.strip()

        if not prompt:
            raise ValueError("Prompt cannot be empty.")

    @property
    def metadata(self) -> dict[str, Any]:
        """
        Provider information.
        """
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "streaming": self.supports_streaming,
            "images": self.supports_images,
            "tools": self.supports_tools,
        }
