from .base_provider import BaseAIProvider


class DeepSeekProvider(BaseAIProvider):

    provider_name = "deepseek"

    async def analyze(self, prompt: str) -> dict:

        return {
            "success": False,
            "provider": self.provider_name,
            "analysis": "",
            "error": "Not implemented"
        }
