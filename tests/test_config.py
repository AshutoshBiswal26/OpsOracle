import pytest

from opsoracle.config import (
    DEFAULT_MAX_EVENTS,
    DEFAULT_MODEL_ID,
    Config,
    load_config,
)
from opsoracle.errors import ConfigError


def test_defaults_when_env_empty():
    cfg = load_config(env={})
    assert cfg == Config()
    assert cfg.region is None
    assert cfg.model_id == DEFAULT_MODEL_ID
    assert cfg.max_events == DEFAULT_MAX_EVENTS
    assert cfg.reasoning_enabled is True


def test_reads_values_from_env():
    cfg = load_config(
        env={
            "OPSORACLE_AWS_REGION": "eu-west-1",
            "OPSORACLE_MODEL_ID": "some.model",
            "OPSORACLE_MAX_EVENTS": "10",
            "OPSORACLE_MAX_TOKENS": "500",
            "OPSORACLE_REASONING_ENABLED": "false",
            "OPSORACLE_MAX_RETRIES": "3",
        }
    )
    assert cfg.region == "eu-west-1"
    assert cfg.model_id == "some.model"
    assert cfg.max_events == 10
    assert cfg.max_tokens == 500
    assert cfg.reasoning_enabled is False
    assert cfg.max_retries == 3


@pytest.mark.parametrize("value", ["yes", "1", "ON", "true"])
def test_bool_truthy(value):
    assert load_config(env={"OPSORACLE_REASONING_ENABLED": value}).reasoning_enabled is True


@pytest.mark.parametrize("value", ["no", "0", "OFF", "false"])
def test_bool_falsy(value):
    assert load_config(env={"OPSORACLE_REASONING_ENABLED": value}).reasoning_enabled is False


def test_invalid_bool_raises():
    with pytest.raises(ConfigError):
        load_config(env={"OPSORACLE_REASONING_ENABLED": "maybe"})


def test_invalid_int_raises():
    with pytest.raises(ConfigError):
        load_config(env={"OPSORACLE_MAX_EVENTS": "lots"})


def test_non_positive_int_raises():
    with pytest.raises(ConfigError):
        load_config(env={"OPSORACLE_MAX_EVENTS": "0"})
