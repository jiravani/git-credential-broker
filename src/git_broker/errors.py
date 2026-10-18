"""Stable public errors that never include upstream output or credentials."""


class BrokerError(Exception):
    """An expected error with a static, safe public message."""


class Denied(BrokerError):
    """The request is invalid or forbidden by policy."""


class ExecutionError(BrokerError):
    """Execution failed; a remote side effect may have occurred."""
