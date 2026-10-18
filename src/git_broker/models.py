"""Strict, immutable wire contracts shared by policy and trusted adapters."""

import hashlib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import Denied


class StrictModel(BaseModel):
    """Reject coercion and unknown fields at every external boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def validate_branch(value: str) -> str:
    """Validate a conservative ASCII branch name, never a revision expression."""
    if (
        value == "HEAD"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", value)
        or value.endswith(("/", "."))
        or ".." in value
        or "//" in value
        or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))
    ):
        raise ValueError("invalid branch name")
    return value


def validate_pattern(value: str) -> str:
    """Accept an exact branch or one trailing subtree wildcard."""
    validate_branch(value[:-2] if value.endswith("/*") else value)
    return value


def matches(branch: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Compare branch names without shell or regex pattern semantics."""
    return any(branch == p or (p.endswith("/*") and branch.startswith(p[:-1])) for p in patterns)


class OperationPlan(StrictModel):
    """Canonical immutable plan; its digest is bound to a single-use capability."""

    operation: Literal["push", "read", "delete"]
    repository: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    branch: str
    expected_old: str = Field(default="", pattern=r"^(?:[0-9a-f]{40})?$")
    commit: str = Field(default="", pattern=r"^(?:[0-9a-f]{40})?$")
    payload_digest: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")

    _branch = field_validator("branch")(validate_branch)

    @model_validator(mode="after")
    def validate_operation(self) -> "OperationPlan":
        """Require only fields meaningful to the selected operation."""
        if self.operation == "push" and (not self.commit or not self.payload_digest):
            raise ValueError("push requires commit and payload digest")
        if self.operation == "read" and (self.commit or self.expected_old or self.payload_digest):
            raise ValueError("read does not accept write fields")
        if self.operation == "delete" and (
            not self.expected_old or self.commit or self.payload_digest
        ):
            raise ValueError("delete requires only the expected old commit")
        return self

    def digest(self) -> str:
        """Return the stable digest of this complete plan."""
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


class Repository(StrictModel):
    """Owner-managed destination. Agents cannot provide a URL or credential reference."""

    backend: Literal["https", "ssh", "local_test"]
    remote: str
    credential: str = ""
    username: str = "git"
    known_hosts: str = ""
    default_branch: str = "main"
    protected: list[str] = Field(default_factory=lambda: ["main", "master", "release/*"])
    automation_reviewed: bool = False

    _default = field_validator("default_branch")(validate_branch)

    @field_validator("protected")
    @classmethod
    def validate_protected(cls, value: list[str]) -> list[str]:
        """Validate every owner-supplied protection pattern."""
        for pattern in value:
            validate_pattern(pattern)
        return value


class Rule(StrictModel):
    """One principal's bounded repository permission; no global wildcard repositories."""

    repository: str
    operations: list[Literal["push", "read", "delete"]]
    branches: list[str]
    deny_branches: list[str] = Field(default_factory=list)

    @field_validator("branches", "deny_branches")
    @classmethod
    def validate_patterns(cls, value: list[str]) -> list[str]:
        """Reject malformed or general-purpose glob expressions."""
        for pattern in value:
            validate_pattern(pattern)
        return value


class Principal(StrictModel):
    """Standing policy for one enrolled runtime, not an unverified model label."""

    rules: list[Rule]
    max_session_seconds: int = Field(default=3600, ge=1, le=86400)
    max_operations: int = Field(default=20, ge=1, le=10000)
    max_grant_seconds: int = Field(default=60, ge=1, le=300)
    enabled: bool = True


class BrokerConfig(StrictModel):
    """Strict owner policy. Replacing it invalidates grants through its revision digest."""

    version: Literal[1] = 1
    repositories: dict[str, Repository]
    principals: dict[str, Principal]
    max_bundle_bytes: int = Field(default=8 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_references(self) -> "BrokerConfig":
        """Reject ambiguous identities and dangling policy references."""
        for key in (*self.repositories, *self.principals):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", key):
                raise ValueError("invalid registered identity")
        for principal in self.principals.values():
            for rule in principal.rules:
                if rule.repository not in self.repositories or not rule.operations or not rule.branches:
                    raise ValueError("invalid policy rule")
        return self

    def revision(self) -> str:
        """Bind grants to all current destination and policy settings."""
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()

    def authorize(self, principal: str, plan: OperationPlan) -> Repository:
        """Apply default-deny policy before obtaining any provider credential."""
        identity = self.principals.get(principal)
        repo = self.repositories.get(plan.repository)
        if identity is None or not identity.enabled or repo is None:
            raise Denied("principal or repository is unavailable")
        if plan.operation != "read":
            if not repo.automation_reviewed:
                raise Denied("repository automation eligibility is not approved")
            if plan.branch == repo.default_branch or matches(plan.branch, repo.protected):
                raise Denied("protected branch writes are forbidden")
        rules = [rule for rule in identity.rules if rule.repository == plan.repository]
        if any(matches(plan.branch, rule.deny_branches) for rule in rules):
            raise Denied("explicit deny rule")
        if not any(
            plan.operation in rule.operations and matches(plan.branch, rule.branches)
            for rule in rules
        ):
            raise Denied("operation is outside standing policy")
        return repo
