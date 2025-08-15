# CAMP Examples

This directory contains example files for testing and demonstrating the CAMP protocol.

## Files

### `sample_map.json`
Example AccessMap configuration showing:
- File-based media reference
- Multiple selector types (byte_offset, byte_stride, segment_hash)
- Local file payload locator

### `payload.bin`
Sample text file used as both:
- Test payload data for encryption
- Media reference for key derivation (via sample_map.json)

## Usage

### Basic Example
```bash
# Encode using the sample configuration
camp encode --map examples/sample_map.json --in examples/payload.bin --artifact demo.art

# Decode back to original
camp decode --map examples/sample_map.json --artifact demo.art --out decrypted.bin

# Verify they match
Compare-Object (Get-Content examples\payload.bin) (Get-Content decrypted.bin)
```

### Custom Configuration
Create your own AccessMap by modifying `sample_map.json`:
1. Change `media_ref` to point to your carrier media
2. Adjust selectors to extract different byte patterns
3. Update `payload_locator` for your encrypted storage location

## Selector Examples

```json
{
  "selectors": [
    // Extract first 32 bytes
    {"type": "byte_offset", "offset": 0, "length": 32},
    
    // Extract every 4th byte starting at position 100, take 20 bytes
    {"type": "byte_stride", "start": 100, "step": 4, "count": 20},
    
    // Include raw bytes from position 500-600 in context
    {"type": "segment_hash", "start": 500, "length": 100}
  ]
}
```
