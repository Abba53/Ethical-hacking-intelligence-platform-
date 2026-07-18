from .base_provider import BaseAIProvider


class GeminiProvider(BaseAIProvider):

    provider_name = "gemini"

    async def analyze(self, prompt: str) -> dict:

        return {
            "success": False,
            "provider": self.provider_name,
            "analysis": "",
            "error": "Not implemented"
        }
