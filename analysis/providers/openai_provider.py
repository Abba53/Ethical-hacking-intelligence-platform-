import os

from openai import AsyncOpenAI

from .base_provider import BaseAIProvider


class OpenAIProvider(BaseAIProvider):

    provider_name = "openai"
    model_name = os.getenv("OPENAI_MODEL", "gpt-5.5")

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "OPENAI_API_KEY environment variable is not set."
                )
            self._client = AsyncOpenAI(api_key=api_key)

        return self._client

    async def analyze(self, prompt: str) -> dict:
        try:
            client = self._get_client()

            response = await client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
        except Exception as exc:
            return {
                "success": False,
                "provider": self.provider_name,
                "analysis": "",
                "error": f"{type(exc).__name__}: {exc}",
            }

        return {
            "success": True,
            "provider": self.provider_name,
            "analysis": response.choices[0].message.content,
            "error": None,
        }
