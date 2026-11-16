import pytest
from pydantic import ValidationError

from app.config import Config, ConfigKongProxy, read_ini_file


def test_the_example_config_loads() -> None:
    config = Config.model_validate(read_ini_file("app.conf.example"))

    assert config.logging.syslog_streams == ["app", "siem", "public_inspect"]
    assert config.logging.console_streams == ["debug"]
    assert config.kong_proxy.enabled is False


def test_an_enabled_proxy_requires_a_url() -> None:
    with pytest.raises(ValidationError, match="url is required"):
        ConfigKongProxy(enabled=True)
