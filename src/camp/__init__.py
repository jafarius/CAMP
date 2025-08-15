"""
CAMP: Ciphered Access Mapping Protocol

A secure, minimal Python implementation of the Ciphered Access Mapping Protocol
for encrypted payload distribution without altering carrier media.

This package provides:
- Core cryptographic functions for secure key derivation
- CAMP protocol implementation for encoding/decoding
- CLI interface for easy operation
- Comprehensive test suite

Example usage:
    >>> from camp.core import encode_payload, decode_payload
    >>> artifact, ciphertext = encode_payload(data, access_map)
    >>> plaintext = decode_payload(artifact, access_map)
"""

__version__ = "1.0.0"
__author__ = "CAMP Development Team"
__email__ = "contact@camp-protocol.org"
__license__ = "MIT"

# Public API
from .core import encode_payload, decode_payload
from .crypto import sha256, canonicalize_json
from .artifact import build_artifact, parse_artifact

__all__ = [
    "encode_payload",
    "decode_payload", 
    "sha256",
    "canonicalize_json",
    "build_artifact",
    "parse_artifact",
]
