"""Encrypted local credential slots, separated from the agent capability store.

The local master-key profile does not defend against theft of the whole vault.
Use the external-key constructor profile for stronger key custody.
"""

import os
import re
from pathlib import Path
from typing import Literal, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import Denied
from .executor import Credential
from .files import atomic_write, private_directory, read_file
from .models import Repository


class CredentialProvider(Protocol):
    """Trusted extension point; never available as an agent-configurable plugin."""

    def get(self, repository: Repository) -> Credential | None:
        """Return credentials only to a trusted executor after authorization."""
        ...


class Vault:
    """AES-256-GCM slots with domain-separated names and bounded secret records."""

    def __init__(self, root: Path, key: bytes) -> None:
        self.root = private_directory(root)
        if len(key) != 32:
            raise Denied("vault key must be exactly 32 bytes")
        self._cipher = AESGCM(key)

    @classmethod
    def local(cls, root: Path, *, initialize: bool = False) -> "Vault":
        """Use an explicit owner-only local key; never generate a lost key on serve."""
        root = private_directory(root)
        key_path = root / "master.key"
        if initialize:
            atomic_write(key_path, AESGCM.generate_key(bit_length=256), replace=False)
        return cls(root, read_file(key_path, 32))

    @staticmethod
    def _name(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
            raise Denied("invalid credential slot")
        return value

    def put(self, name: str, kind: Literal["https", "ssh"], value: bytes) -> None:
        """Enroll or rotate a secret through the owner CLI only."""
        name = self._name(name)
        if kind not in {"https", "ssh"} or not 1 <= len(value) <= 65536:
            raise Denied("invalid credential kind or length")
        if kind == "https" and any(byte < 33 or byte > 126 for byte in value):
            raise Denied("HTTPS token must contain printable non-space ASCII")
        nonce = os.urandom(12)
        domain = f"git-broker/v1/{name}/{kind}".encode()
        ciphertext = self._cipher.encrypt(nonce, value, domain)
        atomic_write(self.root / f"{name}.{kind}.sealed", b"GBV1" + nonce + ciphertext)

    def get(self, repository: Repository) -> Credential | None:
        """Decrypt a registered credential; there is no agent-facing readback API."""
        if repository.backend == "local_test":
            return None
        name = self._name(repository.credential)
        kind = repository.backend
        data = read_file(self.root / f"{name}.{kind}.sealed", 65600)
        if len(data) < 32 or data[:4] != b"GBV1":
            raise Denied("invalid encrypted credential")
        try:
            value = self._cipher.decrypt(data[4:16], data[16:], f"git-broker/v1/{name}/{kind}".encode())
        except InvalidTag:
            raise Denied("credential integrity check failed") from None
        return Credential(value=value, kind=kind)
