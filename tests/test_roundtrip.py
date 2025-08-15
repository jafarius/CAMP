"""Unit tests for CAMP protocol."""

import os
import tempfile
import json
import pytest
from pathlib import Path
from camp.core import encode_payload, decode_payload
from camp.artifact import build_artifact, parse_artifact
from camp.crypto import crc32


def create_test_media_file() -> str:
    """Create a temporary media file for testing."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        # Create test data with known patterns
        test_data = b'CAMP_TEST_MEDIA_' + b'A' * 100 + b'B' * 100 + b'C' * 100
        f.write(test_data)
        return f.name


def create_test_access_map(media_file: str, payload_file: str) -> dict:
    """Create a test AccessMap."""
    return {
        "version": 1,
        "media_ref_type": "file",
        "media_ref": media_file,
        "selectors": [
            {"type": "byte_offset", "offset": 0, "length": 16},
            {"type": "byte_stride", "start": 16, "step": 2, "count": 10},
            {"type": "segment_hash", "start": 50, "length": 20}
        ],
        "payload_locator": {
            "type": "file",
            "value": payload_file
        }
    }


def test_end_to_end_roundtrip():
    """Test complete encode/decode roundtrip."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        media_file = create_test_media_file()
        payload_file = os.path.join(tmpdir, "payload.bin")
        
        try:
            # Create test payload
            original_payload = b"Hello, CAMP! This is a test payload with some data."
            
            # Create access map
            access_map = create_test_access_map(media_file, payload_file)
            
            # Encode
            artifact_string, payload_ciphertext = encode_payload(original_payload, access_map)
            
            # Save payload ciphertext (simulate what CLI would do)
            with open(payload_file, 'wb') as f:
                f.write(payload_ciphertext)
            
            # Decode
            decoded_payload = decode_payload(artifact_string, access_map)
            
            # Verify
            assert decoded_payload == original_payload
            
        finally:
            os.unlink(media_file)


def test_artifact_crc_tamper_detection():
    """Test that CRC detects artifact tampering."""
    with tempfile.TemporaryDirectory() as tmpdir:
        media_file = create_test_media_file()
        payload_file = os.path.join(tmpdir, "payload.bin")
        
        try:
            original_payload = b"Test payload for CRC test"
            access_map = create_test_access_map(media_file, payload_file)
            
            # Encode
            artifact_string, payload_ciphertext = encode_payload(original_payload, access_map)
            
            # Save payload ciphertext
            with open(payload_file, 'wb') as f:
                f.write(payload_ciphertext)
            
            # Tamper with artifact by changing one character
            tampered_artifact = artifact_string[:-1] + ('X' if artifact_string[-1] != 'X' else 'Y')
            
            # Attempt to decode tampered artifact
            with pytest.raises(ValueError, match="Failed to parse artifact"):
                decode_payload(tampered_artifact, access_map)
                
        finally:
            os.unlink(media_file)


def test_wrong_access_map_failure():
    """Test that wrong AccessMap causes decryption failure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        media_file1 = create_test_media_file()
        media_file2 = create_test_media_file()
        payload_file = os.path.join(tmpdir, "payload.bin")
        
        try:
            # Add different content to second media file
            with open(media_file2, 'ab') as f:
                f.write(b'DIFFERENT_CONTENT')
            
            original_payload = b"Test payload for wrong map test"
            access_map1 = create_test_access_map(media_file1, payload_file)
            access_map2 = create_test_access_map(media_file2, payload_file)
            
            # Encode with first access map
            artifact_string, payload_ciphertext = encode_payload(original_payload, access_map1)
            
            # Save payload ciphertext
            with open(payload_file, 'wb') as f:
                f.write(payload_ciphertext)
            
            # Try to decode with second access map (should fail)
            with pytest.raises(Exception):  # Could be ValueError or cryptography exception
                decode_payload(artifact_string, access_map2)
                
        finally:
            os.unlink(media_file1)
            os.unlink(media_file2)


def test_byte_selector_boundary_safety():
    """Test that byte selectors handle boundaries safely."""
    with tempfile.TemporaryDirectory() as tmpdir:
        media_file = create_test_media_file()
        payload_file = os.path.join(tmpdir, "payload.bin")
        
        try:
            # Create access map with selectors that go beyond file boundaries
            access_map = {
                "version": 1,
                "media_ref_type": "file",
                "media_ref": media_file,
                "selectors": [
                    {"type": "byte_offset", "offset": 0, "length": 1000000},  # Way beyond file size
                    {"type": "byte_stride", "start": 100, "step": 1, "count": 1000000},  # Beyond file size
                    {"type": "segment_hash", "start": 200, "length": 1000000}  # Beyond file size
                ],
                "payload_locator": {
                    "type": "file",
                    "value": payload_file
                }
            }
            
            original_payload = b"Boundary test payload"
            
            # Should not raise exception despite out-of-bounds selectors
            artifact_string, payload_ciphertext = encode_payload(original_payload, access_map)
            
            # Save payload ciphertext
            with open(payload_file, 'wb') as f:
                f.write(payload_ciphertext)
            
            # Should decode successfully
            decoded_payload = decode_payload(artifact_string, access_map)
            assert decoded_payload == original_payload
            
        finally:
            os.unlink(media_file)


def test_artifact_build_parse_roundtrip():
    """Test artifact building and parsing."""
    kdf_salt = os.urandom(16)
    nonce = os.urandom(12)
    locator_ct = os.urandom(50)  # Simulated encrypted locator
    payload_ct_tag_hint = os.urandom(4)
    
    # Build artifact
    artifact_string = build_artifact(kdf_salt, nonce, locator_ct, payload_ct_tag_hint)
    
    # Parse artifact
    parsed_salt, parsed_nonce, parsed_locator_ct, parsed_hint = parse_artifact(artifact_string)
    
    # Verify
    assert parsed_salt == kdf_salt
    assert parsed_nonce == nonce
    assert parsed_locator_ct == locator_ct
    assert parsed_hint == payload_ct_tag_hint


if __name__ == '__main__':
    pytest.main([__file__])
