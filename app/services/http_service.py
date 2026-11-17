import logging
from typing import Any, Literal

from gfmodules.logging import correlation_headers
from requests import HTTPError, Response, request
from requests.exceptions import ConnectionError, Timeout

logger = logging.getLogger(__name__)


class HttpService:
    def __init__(
        self,
        endpoint: str,
        timeout: int,
        mtls_cert: str | None,
        mtls_key: str | None,
        verify_ca: str | bool = True,
    ):
        self._endpoint = endpoint
        self._timeout = timeout
        self._mtls_cert = mtls_cert
        self._mtls_key = mtls_key
        self._verify_ca = verify_ca

    def do_request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        sub_route: str = "",
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> Response:
        try:
            cert = (self._mtls_cert, self._mtls_key) if self._mtls_cert and self._mtls_key else None

            url = f"{self._endpoint}/{sub_route}" if sub_route else self._endpoint

            outgoing_headers = {**(headers or {}), **correlation_headers()}

            response = request(
                method=method,
                url=url,
                params=params,
                headers=outgoing_headers,
                json=json,
                data=data,
                timeout=self._timeout,
                cert=cert,
                verify=self._verify_ca,
            )

            return response
        except (ConnectionError, Timeout):
            logger.exception("Request failed")
            raise
        except HTTPError:
            logger.exception("HTTP error occurred")
            raise
