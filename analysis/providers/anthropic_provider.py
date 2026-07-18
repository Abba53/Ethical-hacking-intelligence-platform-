from .base_provider import BaseAIProvider


class AnthropicProvider(BaseAIProvider):

    provider_name = "anthropic"

    async def analyze(self, prompt: str) -> dict:

        return {
            "success": False,
            "provider": self.provider_name,
            "analysis": "",
            "error": "Not implemented"
        }
