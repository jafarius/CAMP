"""
Core CAMP protocol implementation.

This module implements the main CAMP protocol logic for encoding and decoding
payloads using the Ciphered Access Mapping Protocol. It handles:
- Context extraction from media references using selectors
- Master seed derivation from access maps and media context
- Payload encoding and decoding with authenticated encryption

The protocol ensures that encrypted payloads can only be decrypted with both
the correct artifact and the matching access map configuration.
"""

from typing import Dict, Any, List, Tuple
from .crypto import (
    sha256, compute_map_fingerprint, derive_key, derive_nonce2,
    encrypt_aes_gcm, decrypt_aes_gcm, generate_random_bytes
)
from .io import fetch_media_ref


def extract_context_bytes(media_ref: str, media_ref_type: str, selectors: List[Dict[str, Any]]) -> bytes:
    """
    Extract context bytes from MediaRef using selectors.
    
    Processes each selector in order to extract specific bytes from the media
    reference, which are then concatenated to form the context bytes used for
    key derivation.
    
    Args:
        media_ref: Path or URL to the media reference
        media_ref_type: Type of media reference ('file' or 'url')
        selectors: List of selector dictionaries defining extraction rules
        
    Returns:
        Concatenated bytes extracted according to selectors
        
    Note:
        Out-of-bounds selectors are handled gracefully by truncating to
        available data rather than raising exceptions.
    """
    media_bytes = fetch_media_ref(media_ref, media_ref_type)
    context_bytes = b''
    
    for selector in selectors:
        selector_type = selector['type']
        
        if selector_type == 'byte_offset':
            offset = selector['offset']
            length = selector['length']
            end = min(offset + length, len(media_bytes))
            if offset < len(media_bytes):
                context_bytes += media_bytes[offset:end]
                
        elif selector_type == 'byte_stride':
            start = selector['start']
            step = selector['step']
            count = selector['count']
            for i in range(count):
                pos = start + i * step
                if pos < len(media_bytes):
                    context_bytes += media_bytes[pos:pos+1]
                    
        elif selector_type == 'segment_hash':
            start = selector['start']
            length = selector['length']
            end = min(start + length, len(media_bytes))
            if start < len(media_bytes):
                context_bytes += media_bytes[start:end]
    
    return context_bytes


def compute_media_context_digest(media_ref: str, media_ref_type: str, selectors: List[Dict[str, Any]]) -> bytes:
    """
    Compute Media Context Digest (MCD).
    
    The MCD is a SHA-256 hash of all context bytes extracted from the media
    reference using the provided selectors. This digest becomes part of the
    master seed for key derivation.
    
    Args:
        media_ref: Path or URL to the media reference
        media_ref_type: Type of media reference ('file' or 'url')
        selectors: List of selector dictionaries defining extraction rules
        
    Returns:
        32-byte SHA-256 digest of extracted context bytes
    """
    context_bytes = extract_context_bytes(media_ref, media_ref_type, selectors)
    return sha256(context_bytes)


def derive_master_seed(access_map: Dict[str, Any]) -> bytes:
    """
    Derive master seed from AccessMap and MediaRef.
    
    The master seed is computed as SHA-256(MF || MCD) where:
    - MF is the Map Fingerprint (hash of canonicalized AccessMap)
    - MCD is the Media Context Digest (hash of extracted context bytes)
    
    This ensures the encryption key depends on both the access configuration
    and the specific media content.
    
    Args:
        access_map: Complete AccessMap configuration dictionary
        
    Returns:
        32-byte master seed for key derivation
    """
    mf = compute_map_fingerprint(access_map)
    mcd = compute_media_context_digest(
        access_map['media_ref'],
        access_map['media_ref_type'],
        access_map['selectors']
    )
    return sha256(mf + mcd)


def encode_payload(payload_bytes: bytes, access_map: Dict[str, Any]) -> Tuple[str, bytes]:
    """
    Encode payload using CAMP protocol.
    
    Encrypts the payload using keys derived from the access map and media
    reference, then creates a compact artifact containing the metadata
    needed for decryption.
    
    Args:
        payload_bytes: Raw payload data to encrypt
        access_map: AccessMap configuration dictionary
        
    Returns:
        Tuple of (artifact_string, payload_ciphertext) where:
        - artifact_string: Base58-encoded artifact for sharing
        - payload_ciphertext: Encrypted payload to store at locator
        
    Raises:
        ValueError: If access map is invalid or media reference inaccessible
        IOError: If media reference cannot be read
    """
    # Derive master seed and generate random values
    master_seed = derive_master_seed(access_map)
    kdf_salt = generate_random_bytes(16)
    nonce = generate_random_bytes(12)
    
    # Derive encryption key
    key = derive_key(master_seed, kdf_salt)
    
    # Get map fingerprint for associated data
    mf = compute_map_fingerprint(access_map)
    
    # Encrypt payload locator
    payload_locator_string = access_map['payload_locator']['value']
    locator_ct = encrypt_aes_gcm(key, nonce, payload_locator_string.encode('utf-8'), mf)
    
    # Encrypt payload with second nonce
    nonce2 = derive_nonce2(nonce)
    payload_ct = encrypt_aes_gcm(key, nonce2, payload_bytes, mf)
    
    # Compute payload ciphertext tag hint
    payload_ct_tag_hint = sha256(payload_ct)[:4]
    
    # Build artifact (will be handled by artifact.py)
    from .artifact import build_artifact
    artifact_string = build_artifact(kdf_salt, nonce, locator_ct, payload_ct_tag_hint)
    
    return artifact_string, payload_ct


def decode_payload(artifact_string: str, access_map: Dict[str, Any]) -> bytes:
    """
    Decode payload using CAMP protocol.
    
    Reconstructs the encryption key from the access map and media reference,
    then decrypts the payload after fetching it from the encrypted locator.
    
    Args:
        artifact_string: Base58-encoded artifact containing decryption metadata
        access_map: AccessMap configuration dictionary (must match encoding)
        
    Returns:
        Decrypted payload bytes
        
    Raises:
        ValueError: If artifact is corrupted, access map is wrong, or payload
                   ciphertext fails authentication
        IOError: If media reference or payload locator cannot be accessed
        cryptography.exceptions.InvalidTag: If decryption authentication fails
    """
    # Parse artifact
    from .artifact import parse_artifact
    kdf_salt, nonce, locator_ct, payload_ct_tag_hint = parse_artifact(artifact_string)
    
    # Derive master seed and key
    master_seed = derive_master_seed(access_map)
    key = derive_key(master_seed, kdf_salt)
    
    # Get map fingerprint for associated data
    mf = compute_map_fingerprint(access_map)
    
    # Decrypt payload locator
    locator_bytes = decrypt_aes_gcm(key, nonce, locator_ct, mf)
    payload_locator_string = locator_bytes.decode('utf-8')
    
    # Fetch payload ciphertext
    from .io import fetch_payload_ciphertext
    payload_ct = fetch_payload_ciphertext(payload_locator_string, access_map['payload_locator']['type'])
    
    # Verify payload ciphertext tag hint
    if sha256(payload_ct)[:4] != payload_ct_tag_hint:
        raise ValueError("Payload ciphertext tag hint mismatch")
    
    # Decrypt payload
    nonce2 = derive_nonce2(nonce)
    payload_bytes = decrypt_aes_gcm(key, nonce2, payload_ct, mf)
    
    return payload_bytes
