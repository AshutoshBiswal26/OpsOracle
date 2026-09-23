"""Runtime configuration for OpsOracle.

Settings are read from environment variables (documented in ``.env.example``). No secret
values are read or stored here; AWS credentials come from the standard Boto3/IAM
credential chain (requirements 9.1, 9.2).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .errors import ConfigError

# Environment variable names (single source of truth).
ENV_REGION = "OPSORACLE_AWS_REGION"
ENV_MODEL_ID = "OPSORACLE_MODEL_ID"
ENV_MAX_EVENTS = "OPSORACLE_MAX_EVENTS"
ENV_MAX_TOKENS = "OPSORACLE_MAX_TOKENS"
ENV_REASONING_ENABLED = "OPSORACLE_REASONING_ENABLED"
ENV_MAX_RETRIES = "OPSORACLE_MAX_RETRIES"

# Defaults (see design config table).
DEFAULT_MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
DEFAULT_MAX_EVENTS = 50
DEFAULT_MAX_TOKENS = 1500
DEFAULT_REASONING_ENABLED = True
DEFAULT_MAX_RETRIES = 5

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration.

    ``region`` may be ``None``, in which case the Boto3 default region resolution applies.
    This object intentionally holds no credentials.
    """

    region: str | None = None
    model_id: str = DEFAULT_MODEL_ID
    max_events: int = DEFAULT_MAX_EVENTS
    max_tokens: int = DEFAULT_MAX_TOKENS
    reasoning_enabled: bool = DEFAULT_REASONING_ENABLED
    max_retries: int = DEFAULT_MAX_RETRIES


def _get_bool(env: dict[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(f"{key} must be a boolean-like value, got {raw!r}")


def _get_positive_int(env: dict[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{key} must be a positive integer, got {value}")
    return value


def load_config(env: dict[str, str] | None = None) -> Config:
    """Build a :class:`Config` from environment variables.

    Passing ``env`` explicitly (defaults to ``os.environ``) keeps this testable.
    """

    env = os.environ if env is None else env
    region = env.get(ENV_REGION) or None
    model_id = env.get(ENV_MODEL_ID) or DEFAULT_MODEL_ID
    return Config(
        region=region,
        model_id=model_id,
        max_events=_get_positive_int(env, ENV_MAX_EVENTS, DEFAULT_MAX_EVENTS),
        max_tokens=_get_positive_int(env, ENV_MAX_TOKENS, DEFAULT_MAX_TOKENS),
        reasoning_enabled=_get_bool(env, ENV_REASONING_ENABLED, DEFAULT_REASONING_ENABLED),
        max_retries=_get_positive_int(env, ENV_MAX_RETRIES, DEFAULT_MAX_RETRIES),
    )
