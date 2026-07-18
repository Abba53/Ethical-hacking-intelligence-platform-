from .base_provider import BaseAIProvider


class OpenAIProvider(BaseAIProvider):

    provider_name = "openai"

    async def analyze(self, prompt: str) -> dict:

        return {
            "success": False,
            "provider": self.provider_name,
            "analysis": "",
            "error": "Not implemented"
        }
