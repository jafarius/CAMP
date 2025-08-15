"""
I/O operations for CAMP protocol.

This module handles all input/output operations for the CAMP protocol,
including fetching media references, saving/loading artifacts, and
managing payload ciphertext storage.

Supports both local file operations and HTTP/HTTPS URL fetching for
maximum flexibility in media reference sources.
"""

import os
import urllib.request
from pathlib import Path


def fetch_media_ref(media_ref: str, media_ref_type: str) -> bytes:
    """
    Fetch MediaRef content.
    
    Retrieves the content of a media reference for context extraction.
    The media reference is never modified, only read.
    
    Args:
        media_ref: Path or URL to the media reference
        media_ref_type: Type of reference ('file' or 'url')
        
    Returns:
        Raw bytes of the media reference content
        
    Raises:
        ValueError: If media_ref_type is not supported
        IOError: If media reference cannot be accessed
        urllib.error.URLError: If URL cannot be fetched
    """
    if media_ref_type == "url":
        with urllib.request.urlopen(media_ref) as response:
            return response.read()
    elif media_ref_type == "file":
        with open(media_ref, 'rb') as f:
            return f.read()
    else:
        raise ValueError(f"Unsupported media_ref_type: {media_ref_type}")


def fetch_payload_ciphertext(payload_locator: str, locator_type: str) -> bytes:
    """
    Fetch payload ciphertext from locator.
    
    Retrieves encrypted payload data from the location specified in the
    decrypted payload locator.
    
    Args:
        payload_locator: Path or URL where payload ciphertext is stored
        locator_type: Type of locator ('file' or 'url')
        
    Returns:
        Encrypted payload bytes
        
    Raises:
        ValueError: If locator_type is not supported
        IOError: If payload cannot be accessed
        urllib.error.URLError: If URL cannot be fetched
    """
    if locator_type == "url":
        with urllib.request.urlopen(payload_locator) as response:
            return response.read()
    elif locator_type == "file":
        with open(payload_locator, 'rb') as f:
            return f.read()
    else:
        raise ValueError(f"Unsupported locator_type: {locator_type}")


def save_payload_ciphertext(payload_ciphertext: bytes, payload_locator: str, locator_type: str) -> None:
    """
    Save payload ciphertext to locator.
    
    Stores encrypted payload data at the specified location. For file locators,
    creates parent directories as needed. For URL locators, provides instructions
    for manual upload.
    
    Args:
        payload_ciphertext: Encrypted payload bytes to store
        payload_locator: Path or URL where to store the ciphertext
        locator_type: Type of locator ('file' or 'url')
        
    Raises:
        ValueError: If locator_type is not supported
        IOError: If file cannot be written
    
    Note:
        URL locators require manual upload - instructions are printed to console
    """
    if locator_type == "file":
        # Ensure parent directories exist
        Path(payload_locator).parent.mkdir(parents=True, exist_ok=True)
        with open(payload_locator, 'wb') as f:
            f.write(payload_ciphertext)
    elif locator_type == "url":
        print(f"Upload payload ciphertext to: {payload_locator}")
        print(f"Payload size: {len(payload_ciphertext)} bytes")
    else:
        raise ValueError(f"Unsupported locator_type: {locator_type}")


def save_artifact(artifact_string: str, artifact_path: str) -> None:
    """
    Save artifact string to file.
    
    Writes the base58-encoded artifact to a text file with proper line ending.
    Creates parent directories if they don't exist.
    
    Args:
        artifact_string: Base58-encoded artifact
        artifact_path: File path where to save the artifact
        
    Raises:
        IOError: If file cannot be written
    """
    Path(artifact_path).parent.mkdir(parents=True, exist_ok=True)
    with open(artifact_path, 'w') as f:
        f.write(artifact_string + '\n')


def load_artifact(artifact_path: str) -> str:
    """
    Load artifact string from file.
    
    Reads a base58-encoded artifact from a text file, stripping any
    trailing whitespace or newlines.
    
    Args:
        artifact_path: File path to read the artifact from
        
    Returns:
        Base58-encoded artifact string
        
    Raises:
        IOError: If file cannot be read
    """
    with open(artifact_path, 'r') as f:
        return f.read().strip()
