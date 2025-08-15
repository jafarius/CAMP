"""
CLI interface for CAMP protocol.

Provides command-line interface for encoding and decoding operations using
the CAMP protocol. Supports both file and URL-based media references and
payload locators.

Commands:
- encode: Encrypt payload using AccessMap configuration
- decode: Decrypt payload using artifact and AccessMap
"""

import argparse
import json
import sys
from pathlib import Path
from .core import encode_payload, decode_payload
from .io import save_payload_ciphertext, save_artifact, load_artifact


def load_access_map(map_path: str) -> dict:
    """
    Load AccessMap from JSON file.
    
    Args:
        map_path: Path to JSON file containing AccessMap configuration
        
    Returns:
        AccessMap dictionary
        
    Raises:
        SystemExit: If file cannot be loaded or JSON is invalid
    """
    try:
        with open(map_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading access map: {e}", file=sys.stderr)
        sys.exit(1)


def load_payload(payload_path: str) -> bytes:
    """
    Load payload from file.
    
    Args:
        payload_path: Path to payload file to encrypt
        
    Returns:
        Raw payload bytes
        
    Raises:
        SystemExit: If file cannot be read
    """
    try:
        with open(payload_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error loading payload: {e}", file=sys.stderr)
        sys.exit(1)


def save_output(data: bytes, output_path: str) -> None:
    """
    Save output data to file.
    
    Creates parent directories if they don't exist.
    
    Args:
        data: Decrypted payload bytes to save
        output_path: Path where to save the output file
        
    Raises:
        SystemExit: If file cannot be written
    """
    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(data)
    except Exception as e:
        print(f"Error saving output: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_encode(args) -> None:
    """
    Handle encode command.
    
    Encrypts a payload using the specified AccessMap configuration and
    saves both the artifact and encrypted payload.
    
    Args:
        args: Parsed command-line arguments
        
    Raises:
        SystemExit: If encoding fails
    """
    try:
        access_map = load_access_map(args.map)
        payload_bytes = load_payload(args.input)
        
        artifact_string, payload_ciphertext = encode_payload(payload_bytes, access_map)
        
        # Save artifact
        save_artifact(artifact_string, args.artifact)
        
        # Save payload ciphertext
        payload_locator = access_map['payload_locator']['value']
        locator_type = access_map['payload_locator']['type']
        save_payload_ciphertext(payload_ciphertext, payload_locator, locator_type)
        
        print(f"Encoded successfully. Artifact saved to: {args.artifact}")
        
    except Exception as e:
        print(f"Encoding failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_decode(args) -> None:
    """
    Handle decode command.
    
    Decrypts a payload using the artifact and AccessMap configuration.
    
    Args:
        args: Parsed command-line arguments
        
    Raises:
        SystemExit: If decoding fails
    """
    try:
        access_map = load_access_map(args.map)
        artifact_string = load_artifact(args.artifact)
        
        payload_bytes = decode_payload(artifact_string, access_map)
        
        # Save decoded payload
        save_output(payload_bytes, args.output)
        
        print(f"Decoded successfully. Output saved to: {args.output}")
        
    except Exception as e:
        print(f"Decoding failed: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """
    Main CLI entry point.
    
    Parses command-line arguments and dispatches to appropriate handler.
    Provides help text and error handling for invalid usage.
    """
    parser = argparse.ArgumentParser(description="CAMP: Ciphered Access Mapping Protocol")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Encode command
    encode_parser = subparsers.add_parser('encode', help='Encode payload')
    encode_parser.add_argument('--map', required=True, help='AccessMap JSON file')
    encode_parser.add_argument('--in', dest='input', required=True, help='Input payload file')
    encode_parser.add_argument('--artifact', required=True, help='Output artifact file')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode payload')
    decode_parser.add_argument('--map', required=True, help='AccessMap JSON file')
    decode_parser.add_argument('--artifact', required=True, help='Input artifact file')
    decode_parser.add_argument('--out', dest='output', required=True, help='Output payload file')
    
    args = parser.parse_args()
    
    if args.command == 'encode':
        cmd_encode(args)
    elif args.command == 'decode':
        cmd_decode(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
