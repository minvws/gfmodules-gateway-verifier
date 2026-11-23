import json
import logging
from contextlib import ExitStack
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging.testing import capture_stream

from app.config import (
    Config,
    ConfigApp,
    ConfigKongProxy,
    ConfigOin,
    ConfigStats,
    ConfigTelemetry,
    ConfigUvicorn,
    reset_config,
    set_config,
)
from app.container import get_jwt_service
from app.logging.events import Log
from app.routers.validator import router
from app.services.jwt import JwtException

CLIENT_ORGANIZATION_ID = "00000001123456700000"
CLIENT_COMMON_NAME = "common-name"
ORGANIZATION_ID = "00000001123456780000"
OTHER_ORGANIZATION_ID = "00000002987654321000"
CLIENT_ID = "client-1"
TOKEN_ID = "token-1"


@pytest.fixture(autouse=True)
def test_config():
    cfg = Config(
        app=ConfigApp(),
        oin=ConfigOin(
            issuer="test-issuer",
            audience=["test-audience"],
            jwks_url="http://localhost/jwks",
        ),
        telemetry=ConfigTelemetry(endpoint=None, service_name=None, tracer_name=None),
        stats=ConfigStats(host=None, port=None, module_name=None),
        uvicorn=ConfigUvicorn(ssl_base_dir=None, ssl_cert_file=None, ssl_key_file=None),
        kong_proxy=ConfigKongProxy(url="http://kong.example.com"),
    )
    set_config(cfg)
    yield cfg
    reset_config()


@pytest.fixture
def jwt_service():
    mock = MagicMock()
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": ORGANIZATION_ID,
            "act": {"sub": CLIENT_ORGANIZATION_ID, "cn": CLIENT_COMMON_NAME},
            "aud": "test-audience",
            "scope": "test-scope",
            "client_id": CLIENT_ID,
            "jti": TOKEN_ID,
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    mock.verify.return_value = token
    return mock


@pytest.fixture
def client(jwt_service):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_jwt_service] = lambda: jwt_service
    return TestClient(app)


def headers(token: str = "valid.jwt.token") -> dict[str, str]:
    return {
        "x-gf-act-sub": CLIENT_ORGANIZATION_ID,
        "x-gf-act-cn": "common-name",
        "Authorization": "Bearer valid.jwt.token",
    }


def _record(caplog: pytest.LogCaptureFixture, event_id: str) -> logging.LogRecord:
    matches = [r for r in caplog.records if getattr(r, "event_id", None) == event_id]
    assert matches, (
        f"no log record with event_id={event_id}; got {[getattr(r, 'event_id', None) for r in caplog.records]}"
    )
    return matches[-1]


def test_missing_header_logs_005(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers={"x-gf-act-sub": CLIENT_ORGANIZATION_ID, "x-gf-act-cn": CLIENT_COMMON_NAME})
    record = _record(caplog, Log.MISSING_AUTHORIZATION_HEADER.event_id)
    assert record.token_present is False  # type: ignore[attr-defined]
    assert record.certificate_organization_identifier == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    assert not hasattr(record, "request_headers")


def test_missing_gateway_headers_logs_header_names(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get("/validate")
    record = _record(caplog, Log.GATEWAY_HEADERS_INVALID.event_id)
    assert record.levelno == logging.ERROR
    assert record.invalid_headers == ["x-gf-act-sub", "x-gf-act-cn"]  # type: ignore[attr-defined]
    assert record.token_present is False  # type: ignore[attr-defined]


def test_invalid_gateway_header_value_is_never_logged(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    # The empty second domain makes the header invalid; the marker in the first one must still never be logged.
    marker = "INJECTED-MARKER.example.nl,"
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers={**headers(), "x-gf-act-cn": marker})
    record = _record(caplog, Log.GATEWAY_HEADERS_INVALID.event_id)
    assert record.invalid_headers == ["x-gf-act-cn"]  # type: ignore[attr-defined]
    assert record.exc_info is None
    for r in caplog.records:
        assert "INJECTED-MARKER" not in r.getMessage()
        assert "INJECTED-MARKER" not in repr(vars(r))


def test_non_bearer_header_logs_001(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        client.get(
            "/validate",
            headers={
                "x-gf-act-sub": CLIENT_ORGANIZATION_ID,
                "x-gf-act-cn": "common-name",
                "Authorization": "Basic xx",
            },
        )
    record = _record(caplog, Log.MALFORMED_AUTHORIZATION_HEADER.event_id)
    assert record.error_reason == "malformed_authorization_header"  # type: ignore[attr-defined]
    assert record.token_present is True  # type: ignore[attr-defined]


def test_jwt_verify_failure_logs_001(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    jwt_service.verify.side_effect = JwtException("expired")
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.JWT_VERIFICATION_FAILED.event_id)
    assert record.error_reason == "expired"  # type: ignore[attr-defined]


@pytest.mark.parametrize("act", [{}, {"act": "not-an-object"}])
def test_missing_or_invalid_act_logs_missing_act_claim(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture, act: dict[str, str]
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": OTHER_ORGANIZATION_ID,
            "cnf": {"x5t#S256": "validthumbprint"},
            **act,
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        response = client.get("/validate", headers=headers())
    assert response.status_code == 400
    record = _record(caplog, Log.MISSING_ACT_CLAIM.event_id)
    assert record.certificate_organization_identifier == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_missing_act_sub_logs_missing_organization_claim(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": OTHER_ORGANIZATION_ID,
            "act": {"cn": "other-common-name"},
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.MISSING_ORGANIZATION_CLAIM.event_id)
    assert record.certificate_organization_identifier == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_oin_mismatch_logs_003(client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": OTHER_ORGANIZATION_ID,
            "act": {"sub": OTHER_ORGANIZATION_ID, "cn": "other-common-name"},
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.ORGANIZATION_AUTHORIZATION_MISMATCH.event_id)
    assert record.certificate_organization_identifier == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.token_organization_identifier == OTHER_ORGANIZATION_ID  # type: ignore[attr-defined]


def test_common_name_mismatch_logs_common_name_authorization_mismatch(
    client: TestClient, jwt_service: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    token = MagicMock()
    token.claims = json.dumps(
        {
            "sub": ORGANIZATION_ID,
            "act": {"sub": CLIENT_ORGANIZATION_ID, "cn": "other-common-name"},
            "cnf": {"x5t#S256": "validthumbprint"},
        }
    )
    jwt_service.verify.return_value = token
    with caplog.at_level(logging.DEBUG):
        client.get("/validate", headers=headers())
    record = _record(caplog, Log.COMMON_NAME_AUTHORIZATION_MISMATCH.event_id)
    assert record.certificate_organization_identifier == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.token_common_name == "other-common-name"  # type: ignore[attr-defined]
    assert record.client_domains == [CLIENT_COMMON_NAME]  # type: ignore[attr-defined]


_TOKEN = {"sub": ORGANIZATION_ID, "client_id": CLIENT_ID, "jti": TOKEN_ID}
_ACT = {"sub": CLIENT_ORGANIZATION_ID, "cn": CLIENT_COMMON_NAME}


@pytest.mark.parametrize(
    "name,request_headers,claims",
    [
        (
            "MISSING_AUTHORIZATION_HEADER",
            {"x-gf-act-sub": CLIENT_ORGANIZATION_ID, "x-gf-act-cn": CLIENT_COMMON_NAME},
            {**_TOKEN, "act": _ACT},
        ),
        (
            "GATEWAY_HEADERS_INVALID",
            {"x-gf-act-sub": CLIENT_ORGANIZATION_ID, "Authorization": "Bearer valid.jwt.token"},
            {**_TOKEN, "act": _ACT},
        ),
        ("MALFORMED_AUTHORIZATION_HEADER", {**headers(), "Authorization": "Basic xx"}, {**_TOKEN, "act": _ACT}),
        ("JWT_VERIFICATION_FAILED", headers(), JwtException("expired")),
        ("MISSING_ACT_CLAIM", headers(), _TOKEN),
        ("MISSING_ORGANIZATION_CLAIM", headers(), {**_TOKEN, "act": {"cn": CLIENT_COMMON_NAME}}),
        ("ORGANIZATION_AUTHORIZATION_MISMATCH", headers(), {**_TOKEN, "act": {**_ACT, "sub": OTHER_ORGANIZATION_ID}}),
        ("COMMON_NAME_AUTHORIZATION_MISMATCH", headers(), {**_TOKEN, "act": {**_ACT, "cn": "other-common-name"}}),
        ("AUTHENTICATION_SUCCESS", headers(), {**_TOKEN, "act": _ACT}),
    ],
)
def test_every_declared_field_is_filled(
    client: TestClient,
    jwt_service: MagicMock,
    name: str,
    request_headers: dict[str, str],
    claims: dict[str, Any] | JwtException,
) -> None:
    if isinstance(claims, JwtException):
        jwt_service.verify.side_effect = claims
    else:
        jwt_service.verify.return_value.claims = json.dumps(claims)
    event = getattr(Log, name)

    with ExitStack() as stack:
        captured = {
            stream: stack.enter_context(capture_stream(stream, "app.routers.validator")) for stream in event.fields
        }
        client.get("/validate", headers=request_headers)

    for stream, messages in captured.items():
        unfilled = [field for field in event.fields[stream] if messages[-1].get(field) is None]
        assert not unfilled, f"{name} leaves declared {stream} fields empty: {unfilled}"


def test_success_logs_004(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.get("/validate", headers=headers())
    assert response.status_code == 200
    record = _record(caplog, Log.AUTHENTICATION_SUCCESS.event_id)
    assert record.certificate_organization_identifier == CLIENT_ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.represented_organization_identifier == ORGANIZATION_ID  # type: ignore[attr-defined]
    assert record.client_id == CLIENT_ID  # type: ignore[attr-defined]
    assert record.token_id == TOKEN_ID  # type: ignore[attr-defined]
    assert not hasattr(record, "claims")
