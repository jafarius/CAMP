"""
Artifact handling for CAMP protocol.

This module handles the binary artifact format used by CAMP to store encryption
metadata in a compact, tamper-resistant format. Artifacts contain all the
information needed to decrypt a payload when combined with the correct AccessMap.

The artifact format includes integrity protection via CRC-32 checksums and is
encoded in base58 for easy sharing and storage.
"""

import struct
from typing import Tuple
import base58
from .crypto import crc32


def build_artifact(kdf_salt: bytes, nonce: bytes, locator_ct: bytes, payload_ct_tag_hint: bytes) -> str:
    """
    Build artifact from components.
    
    Constructs a binary artifact containing all metadata needed for decryption,
    protected by CRC-32 integrity checking and encoded in base58.
    
    Binary layout:
    - version: 1 byte (0x01)
    - kdf_salt: 16 bytes (PBKDF2 salt)
    - nonce: 12 bytes (AES-GCM nonce)
    - locator_ct_len: 2 bytes big-endian (encrypted locator length)
    - locator_ct: variable bytes (encrypted payload locator)
    - payload_ct_tag_hint: 4 bytes (payload ciphertext hash hint)
    - crc32: 4 bytes big-endian (integrity checksum)
    
    Args:
        kdf_salt: 16-byte random salt for key derivation
        nonce: 12-byte nonce for AES-GCM encryption
        locator_ct: Encrypted payload locator bytes
        payload_ct_tag_hint: First 4 bytes of payload ciphertext hash
        
    Returns:
        Base58-encoded artifact string
        
    Raises:
        ValueError: If any component has incorrect length
    """
    # Artifact binary layout:
    # version: 1 byte (0x01)
    # kdf_salt: 16 bytes
    # nonce: 12 bytes  
    # locator_ct_len: 2 bytes unsigned big-endian
    # locator_ct: variable bytes
    # payload_ct_tag_hint: 4 bytes
    # crc32: 4 bytes
    
    version = b'\x01'
    locator_ct_len = struct.pack('>H', len(locator_ct))
    
    # Build artifact without CRC first
    artifact_data = version + kdf_salt + nonce + locator_ct_len + locator_ct + payload_ct_tag_hint
    
    # Compute and append CRC32
    crc = struct.pack('>I', crc32(artifact_data))
    artifact_binary = artifact_data + crc
    
    # Base58 encode
    return base58.b58encode(artifact_binary).decode('ascii')


def parse_artifact(artifact_string: str) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Parse artifact string into components.
    
    Decodes a base58 artifact string and extracts all metadata components,
    verifying integrity via CRC-32 checksum.
    
    Args:
        artifact_string: Base58-encoded artifact
        
    Returns:
        Tuple of (kdf_salt, nonce, locator_ct, payload_ct_tag_hint) where:
        - kdf_salt: 16-byte PBKDF2 salt
        - nonce: 12-byte AES-GCM nonce
        - locator_ct: Encrypted payload locator bytes
        - payload_ct_tag_hint: 4-byte payload ciphertext hash hint
        
    Raises:
        ValueError: If artifact is malformed, has wrong version, or fails CRC check
    """
    try:
        # Base58 decode
        artifact_binary = base58.b58decode(artifact_string)
        
        # Verify minimum length
        if len(artifact_binary) < 1 + 16 + 12 + 2 + 4 + 4:  # min size
            raise ValueError("Artifact too short")
        
        # Extract CRC and verify
        crc_expected = struct.unpack('>I', artifact_binary[-4:])[0]
        artifact_data = artifact_binary[:-4]
        crc_actual = crc32(artifact_data)
        
        if crc_actual != crc_expected:
            raise ValueError("Artifact CRC mismatch")
        
        # Parse components
        offset = 0
        
        # Version
        version = artifact_data[offset:offset+1]
        if version != b'\x01':
            raise ValueError(f"Unsupported artifact version: {version[0]}")
        offset += 1
        
        # KDF salt
        kdf_salt = artifact_data[offset:offset+16]
        offset += 16
        
        # Nonce
        nonce = artifact_data[offset:offset+12]
        offset += 12
        
        # Locator ciphertext length
        locator_ct_len = struct.unpack('>H', artifact_data[offset:offset+2])[0]
        offset += 2
        
        # Locator ciphertext
        locator_ct = artifact_data[offset:offset+locator_ct_len]
        offset += locator_ct_len
        
        # Payload ciphertext tag hint
        payload_ct_tag_hint = artifact_data[offset:offset+4]
        
        return kdf_salt, nonce, locator_ct, payload_ct_tag_hint
        
    except Exception as e:
        raise ValueError(f"Failed to parse artifact: {e}")
