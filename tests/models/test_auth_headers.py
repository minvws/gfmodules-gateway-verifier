import pytest

from app.models.auth_headers import AuthHeaders


def _headers(**overrides: str) -> dict[str, str]:
    return {"x-gf-act-sub": "00000001123456700000", "x-gf-act-cn": "common-name", **overrides}


def test_accepts_wildcard_and_long_dns_names() -> None:
    long_name = ".".join(["a" * 63] * 3) + ".example.nl"
    auth = AuthHeaders.model_validate(_headers(**{"x-gf-act-cn": f"*.example.nl, {long_name}"}))

    assert auth.client_domains == ["*.example.nl", long_name]


def test_bearer_is_optional() -> None:
    assert AuthHeaders.model_validate(_headers()).bearer is None


@pytest.mark.parametrize(
    "overrides",
    [{"x-gf-act-sub": ""}, {"x-gf-act-cn": ""}, {"x-gf-act-cn": "a,,b"}, {"x-gf-act-cn": "a, "}],
)
def test_rejects_empty_values(overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        AuthHeaders.model_validate(_headers(**overrides))
