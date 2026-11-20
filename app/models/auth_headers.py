from typing import Annotated, Any, Self

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# Conservative charset for header values that end up in logs: no whitespace, control characters or
# separators, so a caller that bypasses the gateway cannot inject content into log lines.
_SAFE_VALUE_PATTERN = r"^[A-Za-z0-9._:\-]{1,128}$"


class GatewayHeadersError(ValueError):
    """The gateway-injected identity headers are missing or invalid. Carries only header names, never values."""

    def __init__(self, invalid_headers: list[str]) -> None:
        super().__init__(f"missing or invalid gateway headers: {', '.join(invalid_headers)}")
        self.invalid_headers = invalid_headers


class AuthHeaders(BaseModel):
    """Identity headers the api-gateway derives from the client's mTLS certificate, plus the client's bearer."""

    model_config = ConfigDict(populate_by_name=True)

    certificate_organization_identifier: Annotated[str, Field(alias="x-gf-act-sub", pattern=_SAFE_VALUE_PATTERN)]
    client_domains: Annotated[list[Annotated[str, Field(pattern=_SAFE_VALUE_PATTERN)]], Field(alias="x-gf-act-cn")]
    # Supplied by the client, not the gateway, so a missing value is a client error and validated by the caller.
    bearer: Annotated[str | None, Field(alias="Authorization")] = None

    @field_validator("client_domains", mode="before")
    @classmethod
    def _split_domains(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [domain.strip() for domain in value.split(",")]
        return value

    @classmethod
    def from_request(cls, req: Request) -> Self:
        headers = req.headers
        data: dict[str, Any] = {}
        for name, field in cls.model_fields.items():
            header_name = field.alias or name
            data[name] = headers.get(header_name)

        try:
            return cls(**data)
        except ValidationError as e:
            raise GatewayHeadersError(cls._header_names(e)) from None

    @classmethod
    def _header_names(cls, error: ValidationError) -> list[str]:
        names: list[str] = []
        for err in error.errors(include_input=False):
            field_name = str(err["loc"][0]) if err["loc"] else ""
            field = cls.model_fields.get(field_name)
            header = (field.alias if field else None) or field_name
            if header not in names:
                names.append(header)
        return names
