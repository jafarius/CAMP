"""
Cryptographic utilities for CAMP protocol.

This module provides the core cryptographic primitives used throughout the CAMP
implementation, including hashing, key derivation, and authenticated encryption.

All functions follow cryptographic best practices and use well-established
algorithms from the Python cryptography library.
"""

import hashlib
import json
import os
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import zlib


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Input bytes to hash
        
    Returns:
        32-byte SHA-256 digest
        
    Example:
        >>> digest = sha256(b"hello world")
        >>> len(digest)
        32
    """
    return hashlib.sha256(data).digest()


def crc32(data: bytes) -> int:
    """
    Compute CRC-32 checksum of data.
    
    Args:
        data: Input bytes to checksum
        
    Returns:
        32-bit CRC checksum as unsigned integer
        
    Note:
        Uses zlib.crc32 with masking to ensure unsigned result
    """
    return zlib.crc32(data) & 0xffffffff


def canonicalize_json(obj: Dict[str, Any]) -> str:
    """
    Canonicalize JSON object for consistent hashing.
    
    Produces deterministic JSON representation by sorting keys and using
    compact separators without extra whitespace.
    
    Args:
        obj: Dictionary to canonicalize
        
    Returns:
        Canonical JSON string representation
        
    Example:
        >>> canonicalize_json({"b": 2, "a": 1})
        '{"a":1,"b":2}'
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def compute_map_fingerprint(access_map: Dict[str, Any]) -> bytes:
    """
    Compute Map Fingerprint (MF) from AccessMap.
    
    The Map Fingerprint is a SHA-256 hash of the canonicalized AccessMap JSON,
    used to bind the encryption to a specific access configuration.
    
    Args:
        access_map: AccessMap dictionary
        
    Returns:
        32-byte SHA-256 fingerprint
    """
    canonical = canonicalize_json(access_map)
    return sha256(canonical.encode('utf-8'))


def derive_key(master_seed: bytes, salt: bytes, iterations: int = 200000) -> bytes:
    """
    Derive encryption key using PBKDF2-HMAC-SHA256.
    
    Uses industry-standard PBKDF2 with SHA-256 HMAC and high iteration count
    for secure key derivation from the master seed.
    
    Args:
        master_seed: 32-byte master seed from MF||MCD
        salt: 16-byte random salt
        iterations: PBKDF2 iteration count (default: 200,000)
        
    Returns:
        32-byte derived encryption key
        
    Raises:
        ValueError: If master_seed is not 32 bytes or salt is not 16 bytes
    """
    if len(master_seed) != 32:
        raise ValueError("Master seed must be 32 bytes")
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_seed)


def derive_nonce2(nonce: bytes) -> bytes:
    """
    Derive second nonce for payload encryption.
    
    Creates a second nonce by hashing the original nonce with a constant,
    ensuring different nonces for locator and payload encryption.
    
    Args:
        nonce: Original 12-byte nonce
        
    Returns:
        12-byte derived nonce
        
    Raises:
        ValueError: If nonce is not 12 bytes
    """
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    return sha256(nonce + b'\x01')[:12]


def encrypt_aes_gcm(key: bytes, nonce: bytes, plaintext: bytes, 
                   associated_data: Optional[bytes] = None) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    
    Provides authenticated encryption with AES-256 in Galois/Counter Mode,
    ensuring both confidentiality and authenticity.
    
    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce (must be unique per key)
        plaintext: Data to encrypt
        associated_data: Optional additional authenticated data
        
    Returns:
        Ciphertext including authentication tag
        
    Raises:
        ValueError: If key or nonce have incorrect lengths
        cryptography.exceptions.InvalidKey: If encryption fails
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for AES-GCM")
        
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, associated_data)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, 
                   associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    
    Decrypts and verifies authenticated ciphertext, ensuring both the
    ciphertext and associated data are authentic.
    
    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce used for encryption
        ciphertext: Encrypted data with authentication tag
        associated_data: Optional additional authenticated data
        
    Returns:
        Decrypted plaintext
        
    Raises:
        ValueError: If key or nonce have incorrect lengths
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for AES-GCM")
        
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Uses the operating system's cryptographically secure random number
    generator for generating salts, nonces, and other random values.
    
    Args:
        length: Number of random bytes to generate
        
    Returns:
        Cryptographically secure random bytes
        
    Raises:
        ValueError: If length is negative
    """
    if length < 0:
        raise ValueError("Length must be non-negative")
    return os.urandom(length)
