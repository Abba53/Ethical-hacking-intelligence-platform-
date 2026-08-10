def format_list_item(item) -> str:
    """
    Renders a single list item from an AI report field as plain text.

    Schemas declare these fields as list[str], but LLMs don't always
    follow that strictly — some providers return a dict (e.g.
    {"recommendation": "...", "priority": "..."}) instead of a plain
    string. This normalizes either shape into readable text instead
    of letting a raw dict repr leak into output.
    """
    if isinstance(item, dict):
        for key in (
            "recommendation", "description", "entry_point",
            "asset", "issue", "finding", "name", "summary",
        ):
            value = item.get(key)
            if value:
                return str(value)
        return ", ".join(f"{k}: {v}" for k, v in item.items())

    return str(item)
