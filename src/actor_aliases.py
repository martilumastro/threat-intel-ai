"""Known threat-actor alias handling."""

import json

from common import PROJECT_DIR

ALIASES_PATH = PROJECT_DIR / "knowledge" / "actor_aliases.json"


def load_actor_aliases() -> dict[str, list[str]]:
    """Load and validate the local actor-alias catalogue."""
    try:
        with ALIASES_PATH.open("r", encoding="utf-8") as file_handle:
            aliases = json.load(file_handle)
    except FileNotFoundError as error:
        raise TypeError(f"Alias catalogue not found: {ALIASES_PATH}") from error
    except json.JSONDecodeError as error:
        raise TypeError(f"Alias catalogue is not valid JSON: {error}") from error

    if not isinstance(aliases, dict):
        raise TypeError("Alias catalogue must be a JSON object.")

    for canonical_name, known_aliases in aliases.items():
        if not isinstance(canonical_name, str):
            raise TypeError("Each canonical actor name must be a string.")
        if not isinstance(known_aliases, list) or not all(
            isinstance(alias, str) for alias in known_aliases
        ):
            raise TypeError(
                f"Aliases for '{canonical_name}' must be a list of strings."
            )

    return aliases


def canonical_actor_name(actor_name: str, aliases: dict[str, list[str]]) -> str:
    """Return the canonical actor name when a known alias is supplied."""
    normalized_name = actor_name.strip().casefold()

    for canonical_name, known_aliases in aliases.items():
        all_names = [canonical_name, *known_aliases]

        if any(normalized_name == name.strip().casefold() for name in all_names):
            return canonical_name

    return actor_name