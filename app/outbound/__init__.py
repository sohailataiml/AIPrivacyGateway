"""The shared outbound boundary: one serializer, one scan, one attestation.

Everything the gateway transmits to a provider passes through
:class:`~app.outbound.gateway.OutboundGateway`, whichever route asked for it.
Before this package existed the document path had its own copy and the chat path
had none, which is the shape of problem ADR-0024 was written about: a control
that exists on one path is a control that can be forgotten on the other.
"""

from app.outbound.gateway import (
    Attestation,
    Invoker,
    OutboundBlockedError,
    OutboundGateway,
    Transmission,
)
from app.outbound.scan import REDACTION_PREFIX, OutboundScan, ScanVerdict, scan_outbound
from app.outbound.serialization import (
    SERIALIZATION_VERSION,
    outbound_segments,
    outbound_text,
    serialize_outbound,
)

__all__ = [
    "REDACTION_PREFIX",
    "SERIALIZATION_VERSION",
    "Attestation",
    "Invoker",
    "OutboundBlockedError",
    "OutboundGateway",
    "OutboundScan",
    "ScanVerdict",
    "Transmission",
    "outbound_segments",
    "outbound_text",
    "scan_outbound",
    "serialize_outbound",
]
