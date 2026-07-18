import json
import re
from typing import Any, Dict, List, Union


class JSONParser:
    """
    Production-grade JSON parser for LLM responses.

    Features:
    - Removes Markdown code fences.
    - Extracts JSON from surrounding text.
    - Supports JSON objects and arrays.
    - Provides descriptive exceptions.
    - Optional schema validation.
    """

    @staticmethod
    def _remove_code_fences(text: str) -> str:
        text = text.strip()

        if text.startswith("```"):
            lines = text.splitlines()

            if lines:
                lines = lines[1:]

            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]

            text = "\n".join(lines)

        return text.strip()

    @staticmethod
    def _extract_json(text: str) -> str:
        """
        Extract first JSON object or array from text.
        """

        match = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)

        if match:
            return match.group(1)

        return text

    @classmethod
    def parse(
        cls,
        response: str,
        required_keys: List[str] | None = None,
    ) -> Union[Dict[str, Any], List[Any]]:

        if not response:
            raise ValueError("Empty response received.")

        response = cls._remove_code_fences(response)
        response = cls._extract_json(response)

        try:
            data = json.loads(response)

        except json.JSONDecodeError as e:
            raise ValueError(
                f"Invalid JSON.\n"
                f"Reason: {e.msg}\n"
                f"Line: {e.lineno}, Column: {e.colno}"
            ) from e

        if required_keys and isinstance(data, dict):
            missing = [
                key
                for key in required_keys
                if key not in data
            ]

            if missing:
                raise ValueError(
                    f"Missing required keys: {', '.join(missing)}"
                )

        return data
