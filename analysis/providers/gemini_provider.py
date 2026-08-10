import os

import httpx

from analysis.models.ai_response import AIResponse

from .base_provider import BaseAIProvider


class GeminiProvider(BaseAIProvider):

    provider_name = "gemini"
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")

        if not self.api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set."
            )

    async def analyze(self, prompt: str) -> AIResponse:

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/"
            f"models/{self.model_name}:generateContent"
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:

                response = await client.post(
                    url,
                    params={
                        "key": self.api_key
                    },
                    json=payload,
                )

                response.raise_for_status()

                data = response.json()

                text = (
                    data["candidates"][0]
                    ["content"]["parts"][0]
                    ["text"]
                )

                return AIResponse(
                    success=True,
                    provider=self.provider_name,
                    report_type="",
                    analysis=text,
                    raw_response=data,
                )

        except Exception as exc:

            return AIResponse(
                success=False,
                provider=self.provider_name,
                report_type="",
                analysis=None,
                error=f"{type(exc).__name__}: {exc}",
            )
