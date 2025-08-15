# CAMP: Ciphered Access Mapping Protocol

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](tests/)

A secure, minimal Python implementation of the Ciphered Access Mapping Protocol (CAMP) for encrypted payload distribution without altering carrier media.

## Overview

CAMP enables encrypted data distribution using a novel approach:
- **Carrier media remains untouched** - Uses existing files/URLs as cryptographic context
- **Compact artifacts** - Only a short base58 string needs to be shared
- **Access maps as keys** - The encryption key is derived from user-supplied logic
- **Strong security** - AES-256-GCM with PBKDF2 key derivation

## Key Features

- 🔒 **AES-256-GCM encryption** with authenticated encryption
- 🔑 **Deterministic key derivation** from media context and access maps
- 📦 **Compact artifacts** encoded in base58 format
- 🛡️ **Tamper detection** with CRC-32 checksums and authentication tags
- 🌐 **Flexible media sources** supporting both files and URLs
- ⚡ **CLI interface** for easy encoding/decoding operations

## Installation

### From Source
```bash
git clone https://github.com/yourusername/camp.git
cd camp
pip install -e .
```

### Requirements
- Python 3.11 or higher
- cryptography >= 41.0.0
- base58 >= 2.1.0

## Quick Start

### 1. Create an Access Map
```json
{
  "version": 1,
  "media_ref_type": "file",
  "media_ref": "path/to/your/media.jpg",
  "selectors": [
    {"type": "byte_offset", "offset": 0, "length": 16},
    {"type": "byte_stride", "start": 100, "step": 3, "count": 10}
  ],
  "payload_locator": {
    "type": "file",
    "value": "encrypted_payload.bin"
  }
}
```

### 2. Encode Your Data
```bash
camp encode --map access_map.json --in secret.txt --artifact secret.art
```

### 3. Decode Your Data
```bash
camp decode --map access_map.json --artifact secret.art --out decrypted.txt
```

## Access Map Configuration

### Selector Types

**Byte Offset**: Extract consecutive bytes
```json
{"type": "byte_offset", "offset": 100, "length": 32}
```

**Byte Stride**: Extract bytes at regular intervals
```json
{"type": "byte_stride", "start": 0, "step": 8, "count": 16}
```

**Segment Hash**: Include raw segment bytes in context
```json
{"type": "segment_hash", "start": 200, "length": 64}
```

### Media Reference Types

- **File**: `"media_ref_type": "file"` - Local file path
- **URL**: `"media_ref_type": "url"` - HTTP/HTTPS URL

## Security Model

1. **Map Fingerprint (MF)**: SHA-256 of canonicalized AccessMap JSON
2. **Media Context Digest (MCD)**: SHA-256 of bytes extracted via selectors
3. **Master Seed**: SHA-256(MF || MCD)
4. **Encryption Key**: PBKDF2-HMAC-SHA256(master_seed, salt, 200k iterations)

## API Reference

### Core Functions

```python
from camp.core import encode_payload, decode_payload

# Encode
artifact, ciphertext = encode_payload(payload_bytes, access_map)

# Decode  
plaintext = decode_payload(artifact_string, access_map)
```

## Testing

Run the comprehensive test suite:
```bash
pytest tests/ -v
```

Tests cover:
- End-to-end encoding/decoding
- Tamper detection
- Wrong key rejection
- Boundary condition safety
- Artifact format validation

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Considerations

- Keep Access Maps secure - they are the cryptographic keys
- Verify artifact integrity before processing
- Use strong, unpredictable media sources for key derivation
- Regularly rotate Access Maps for long-term security

## Acknowledgments

- Built with [cryptography](https://cryptography.io/) library
- Uses [base58](https://github.com/keis/base58) encoding
- Follows cryptographic best practices
