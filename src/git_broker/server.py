"""Bounded agent API. Serve on an owner-managed Unix socket, never a public port."""

import asyncio
import base64
import binascii
import json

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from .errors import BrokerError, Denied
from .models import OperationPlan, StrictModel
from .service import Broker


class RequestBody(StrictModel):
    """One typed transport envelope; secrets never appear in error responses."""

    action: str
    plan: OperationPlan | None = None
    grant: str = ""
    payload: str = ""
    request_id: str = ""
    operation_id: str = ""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class AgentAPI:
    """Bound request size and concurrency before invoking trusted orchestration."""

    def __init__(self, broker: Broker, max_body: int = 23_000_000) -> None:
        self.broker = broker
        self.max_body = max_body
        self.busy = False
        self.app = Starlette(routes=[Route("/rpc", self.rpc, methods=["POST"])])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)

    async def rpc(self, request: Request) -> JSONResponse:
        """Reject browsers, ambiguous auth, oversized input, and overlapping work."""
        if self.busy:
            return JSONResponse({"error": "broker busy"}, status_code=429)
        self.busy = True
        worker: asyncio.Task[dict[str, object]] | None = None
        try:
            authorization = request.headers.getlist("authorization")
            if (len(authorization) != 1 or not authorization[0].startswith("Bearer ")
                    or "origin" in request.headers):
                raise Denied("invalid authentication")
            session = authorization[0][7:]
            self.broker.scope(session)
            body = bytearray()
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > self.max_body:
                        raise Denied("request too large")
            data = RequestBody.model_validate(json.loads(body, object_pairs_hook=_unique))
            worker = asyncio.create_task(asyncio.to_thread(self.dispatch, session, data))
            worker.add_done_callback(self._finished)
            result = await asyncio.shield(worker)
            return JSONResponse(result)
        except (BrokerError, ValueError, ValidationError, TimeoutError, binascii.Error):
            return JSONResponse({"error": "request denied or execution uncertain"}, status_code=400)
        except Exception:
            return JSONResponse({"error": "internal failure; do not replay writes"}, status_code=500)
        finally:
            if worker is None:
                self.busy = False

    def _finished(self, worker: asyncio.Task[dict[str, object]]) -> None:
        """Keep admission closed while cancelled requests still have a live worker."""
        self.busy = False
        if not worker.cancelled():
            worker.exception()

    def dispatch(self, session: str, data: RequestBody) -> dict[str, object]:
        """Expose no owner, credential, arbitrary shell, or policy-edit operations."""
        if data.action == "scope":
            return self.broker.scope(session)
        if data.action == "operation":
            return self.broker.operation(session, data.operation_id)
        if data.plan is None:
            raise Denied("plan required")
        if data.action == "grant":
            return self.broker.request_grant(session, data.plan)
        if data.action == "execute":
            payload = base64.b64decode(data.payload, validate=True)
            return self.broker.execute(session, data.grant, data.plan, payload, data.request_id)
        raise Denied("unsupported action")
