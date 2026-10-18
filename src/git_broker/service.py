"""Authorization orchestration, independent of MCP and Git transport implementations."""

import hashlib
from pathlib import Path

from .errors import BrokerError, Denied, ExecutionError
from .executor import Executor
from .models import OperationPlan
from .policy import PolicySource, dispatch_lock
from .state import State
from .vault import CredentialProvider


class Broker:
    """Revalidate standing policy and exact-plan capabilities before every dispatch."""

    def __init__(
        self,
        state: State,
        policy: PolicySource,
        credentials: CredentialProvider,
        executor: Executor,
        root: Path,
    ) -> None:
        self.state = state
        self.policy = policy
        self.credentials = credentials
        self.executor = executor
        self.root = root

    def scope(self, session: str) -> dict[str, object]:
        """Show current effective identity/policy without credentials or private URLs."""
        identity = self.state.authenticate(session)
        principal = str(identity["principal"])
        config = self.policy.load()
        owner = config.principals.get(principal)
        if owner is None or not owner.enabled:
            raise Denied("principal is disabled")
        return {
            "principal": principal,
            "session_id": identity["id"],
            "expires": identity["expires"],
            "remaining": identity["remaining"],
            "rules": [rule.model_dump() for rule in owner.rules],
            "revision": config.revision(),
        }

    def request_grant(self, session: str, plan: OperationPlan, ttl: int = 60) -> dict[str, object]:
        """Automatically attenuate an authenticated session under standing policy."""
        if type(ttl) is not int or ttl < 1:
            raise Denied("invalid grant lifetime")
        identity = self.state.authenticate(session)
        principal = str(identity["principal"])
        config = self.policy.load()
        config.authorize(principal, plan)
        seconds = min(ttl, config.principals[principal].max_grant_seconds)
        return self.state.request_grant(session, plan, config.revision(), seconds)

    def execute(
        self,
        session: str,
        grant: str,
        plan: OperationPlan,
        payload: bytes,
        request_id: str,
    ) -> dict[str, object]:
        """Dispatch a plan at most once; retries return durable operation state."""
        with dispatch_lock(self.root):
            identity = self.state.authenticate(session)
            principal = str(identity["principal"])
            config = self.policy.load()
            repository = config.authorize(principal, plan)
            if len(payload) > config.max_bundle_bytes:
                raise Denied("payload exceeds configured limit")
            if plan.operation == "push":
                if hashlib.sha256(payload).hexdigest() != plan.payload_digest:
                    raise Denied("payload does not match grant")
            elif payload:
                raise Denied("operation does not accept a payload")
            operation = self.state.begin(session, grant, plan, config.revision(), request_id)
            if not operation["newly_reserved"]:
                return operation
            operation_id = str(operation["id"])
            try:
                credential = self.credentials.get(repository)
                result = self.executor.execute(repository, plan, payload, credential)
                self.state.finish(operation_id, result, True)
            except Exception as exc:
                # A remote dispatch may have succeeded. Never refund or auto-retry.
                self.state.finish(operation_id, None, False)
                if isinstance(exc, BrokerError):
                    raise
                raise ExecutionError("execution failed; inspect operation before retry") from None
            return self.state.get_operation(session, operation_id)

    def operation(self, session: str, operation_id: str) -> dict[str, object]:
        """Return only the authenticated session's operation result."""
        self.scope(session)
        return self.state.get_operation(session, operation_id)
