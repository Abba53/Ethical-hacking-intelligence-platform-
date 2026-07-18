import os

from .openai_provider import OpenAIProvider
from .gemini_provider import GeminiProvider
from .deepseek_provider import DeepSeekProvider
from .anthropic_provider import AnthropicProvider
from .local_provider import LocalProvider


def get_provider():

    provider = os.getenv("AI_PROVIDER", "gemini").lower()

    mapping = {
        "openai": OpenAIProvider,
        "gemini": GeminiProvider,
        "deepseek": DeepSeekProvider,
        "anthropic": AnthropicProvider,
        "local": LocalProvider,
    }

    return mapping.get(provider, GeminiProvider)()
