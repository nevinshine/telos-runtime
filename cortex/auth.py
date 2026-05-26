"""Authentication helpers for Cortex gRPC clients and servers."""

from __future__ import annotations

import hmac
import os
from typing import Iterable

import grpc


AUTH_TOKEN_ENV = "TELOS_CORTEX_AUTH_TOKEN"
AUTHORIZATION_HEADER = "authorization"
LEGACY_TOKEN_HEADER = "x-telos-auth-token"


def get_auth_token(explicit: str | None = None) -> str:
    """Return the configured Cortex auth token or raise a clear error."""
    token = explicit or os.getenv(AUTH_TOKEN_ENV, "")
    token = token.strip()
    if not token:
        raise RuntimeError(
            f"Cortex gRPC auth token is required. Set {AUTH_TOKEN_ENV} "
            "or pass --auth-token when starting Cortex."
        )
    return token


def auth_metadata(token: str | None = None) -> tuple[tuple[str, str], ...]:
    """Build gRPC metadata for authenticated local Cortex clients."""
    return ((AUTHORIZATION_HEADER, f"Bearer {get_auth_token(token)}"),)


def _metadata_values(
    metadata: Iterable[tuple[str, str]] | None,
    key: str,
) -> list[str]:
    wanted = key.lower()
    return [value for name, value in (metadata or ()) if name.lower() == wanted]


def metadata_has_valid_token(
    metadata: Iterable[tuple[str, str]] | None,
    expected_token: str,
) -> bool:
    """Validate bearer or legacy token metadata using constant-time compare."""
    for value in _metadata_values(metadata, AUTHORIZATION_HEADER):
        scheme, _, credential = value.partition(" ")
        if scheme.lower() == "bearer" and hmac.compare_digest(
            credential.strip(),
            expected_token,
        ):
            return True

    for value in _metadata_values(metadata, LEGACY_TOKEN_HEADER):
        if hmac.compare_digest(value.strip(), expected_token):
            return True

    return False


class CortexAuthInterceptor(grpc.ServerInterceptor):
    """Require local gRPC callers to present the configured auth token."""

    def __init__(self, token: str):
        self.token = get_auth_token(token)

    def intercept_service(self, continuation, handler_call_details):
        import uuid
        from cortex.logger import correlation_id
        
        # Assign a unique correlation ID to the current ContextVar for structured logging
        correlation_id.set(str(uuid.uuid4()))
        
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        if metadata_has_valid_token(
            handler_call_details.invocation_metadata,
            self.token,
        ):
            return handler

        def deny(request, context):
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "missing or invalid Cortex auth token",
            )

        return grpc.unary_unary_rpc_method_handler(
            deny,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )
