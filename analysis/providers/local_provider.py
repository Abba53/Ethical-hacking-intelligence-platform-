from .base_provider import BaseAIProvider


class LocalProvider(BaseAIProvider):

    provider_name = "local"

    async def analyze(self, prompt: str) -> dict:

        return {
            "success": False,
            "provider": self.provider_name,
            "analysis": "",
            "error": "Not implemented"
        }
