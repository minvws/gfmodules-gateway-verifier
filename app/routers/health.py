import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import get_jwt_service
from app.logging.events import Log
from app.services.jwt import JWTService

logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get(
    "/health",
    summary="Health Check",
    description="health check for all dependent API services and components.",
    status_code=200,
    responses={
        200: {
            "description": "Health check completed (may contain unhealthy components)",
            "content": {
                "application/json": {
                    "examples": {
                        "all_healthy": {
                            "summary": "All services healthy",
                            "value": {
                                "status": "ok",
                            },
                        },
                    }
                }
            },
        },
        500: {"description": "Unexpected error during health check execution"},
        503: {
            "description": "One or more components are unhealthy",
            "content": {
                "application/json": {
                    "examples": {
                        "some_unhealthy": {
                            "summary": "Some services unhealthy",
                            "value": {
                                "status": "error",
                            },
                        },
                    }
                }
            },
        },
    },
    tags=["Health"],
)
def health(jwt_service: Annotated[JWTService, Depends(get_jwt_service)]) -> JSONResponse:
    logger.debug("Checking application health")

    errors = {"jwks_url": jwt_service.health_error()}
    components = {name: ok_or_error(error is None) for name, error in errors.items()}
    healthy = all(error is None for error in errors.values())

    for name, error in errors.items():
        if error is not None:
            gflog.emit(
                logger,
                Log.HEALTH_UNHEALTHY,
                "Health check unhealthy",
                fields={"component": name, "status": "error", "error_detail": error},
            )

    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": ok_or_error(healthy),
            "components": components,
        },
    )
