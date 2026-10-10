"""Pinned QRL v1 protobuf source, generated binding, and descriptor identities."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .errors import IntegrityError
from .vendor import qrl_pb2


PROTOBUF_SCHEMA_SHA256 = "0d70a3372c4668a1bf4fd42983ae01f2e0fb54b4030b808bbea78e5adadb23f0"
PROTOBUF_BINDING_SHA256 = "a6d9fdd3d3490ae04171c4a6fd777bfc42ca2f38f73788893069cc366f7cd4d3"
PROTOBUF_DESCRIPTOR_SHA256 = "9e65bd19e719a916f46ff2f3b9e5696996c2ae0203d0f9068e707395baf357f0"


def schema_fingerprints() -> dict[str, str]:
    """Return digests of the shipped schema, binding file, and imported descriptor."""
    proto_path = Path(__file__).parent / "vendor" / "qrl.proto"
    binding_path = Path(__file__).parent / "vendor" / "qrl_pb2.py"
    try:
        proto_bytes = proto_path.read_bytes()
    except OSError as error:
        raise IntegrityError("vendored qrl.proto is missing or unreadable") from error
    try:
        binding_bytes = binding_path.read_bytes()
    except OSError as error:
        raise IntegrityError("vendored qrl_pb2.py is missing or unreadable") from error
    return {
        "protobuf_schema_sha256": hashlib.sha256(proto_bytes).hexdigest(),
        "protobuf_binding_sha256": hashlib.sha256(binding_bytes).hexdigest(),
        "protobuf_descriptor_sha256": hashlib.sha256(qrl_pb2.DESCRIPTOR.serialized_pb).hexdigest(),
    }


def assert_pinned_schema() -> None:
    """Fail if the shipped .proto or imported generated binding has changed."""
    fingerprints = schema_fingerprints()
    if fingerprints["protobuf_schema_sha256"] != PROTOBUF_SCHEMA_SHA256:
        raise IntegrityError("vendored qrl.proto differs from the pinned schema")
    if fingerprints["protobuf_binding_sha256"] != PROTOBUF_BINDING_SHA256:
        raise IntegrityError("vendored qrl_pb2.py differs from the pinned binding")
    if fingerprints["protobuf_descriptor_sha256"] != PROTOBUF_DESCRIPTOR_SHA256:
        raise IntegrityError("generated qrl_pb2 descriptor differs from the pinned schema")
