import os

from .openai_provider import OpenAIProvider
from .gemini_provider import GeminiProvider
from .deepseek_provider import DeepSeekProvider
from .anthropic_provider import AnthropicProvider
from .local_provider import LocalProvider
from .groq_provider import GroqProvider
from .cerebras_provider import CerebrasProvider
from .together_provider import TogetherProvider
from .fireworks_provider import FireworksProvider
from .openrouter_provider import OpenRouterProvider
from .nvidia_nim_provider import NvidiaNimProvider
from .ollama_provider import OllamaProvider
from .vllm_provider import VLLMProvider
from .omniroute_provider import OmniRouteProvider


def get_provider():

    provider = os.getenv("AI_PROVIDER", "gemini").lower()

    mapping = {
        "openai": OpenAIProvider,
        "gemini": GeminiProvider,
        "deepseek": DeepSeekProvider,
        "anthropic": AnthropicProvider,
        "local": LocalProvider,
        "groq": GroqProvider,
        "cerebras": CerebrasProvider,
        "together": TogetherProvider,
        "fireworks": FireworksProvider,
        "openrouter": OpenRouterProvider,
        "nvidia_nim": NvidiaNimProvider,
        "ollama": OllamaProvider,
        "vllm": VLLMProvider,
        "omniroute": OmniRouteProvider,
    }

    return mapping.get(provider, GeminiProvider)()
