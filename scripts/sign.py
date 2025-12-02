#!/usr/bin/env python3
"""
DJI Firmware Signing Script

This script creates signed DJI firmware images that can be verified by og_verify
and flashed to DJI drones. It performs the inverse operation of verify.c:
instead of verifying existing signatures, it creates new signatures for
modified firmware.

PURPOSE
-------
DJI drones verify firmware signatures before flashing. This script allows you
to sign modified firmware with the "Slack" keys (SLAK/SLEK) so that og_verify
can validate them. This is useful for:
- Custom firmware modifications
- Research and development
- Understanding DJI's firmware structure

HOW IT WORKS
------------
1. Read the firmware binary file
2. Pad the data to AES block boundaries
3. Optionally encrypt the data with AES-128-CBC
4. Generate a random scramble key, encrypt it with SLEK
5. Create the DJI image header with all required fields
6. Compute SHA-256 hash of the payload
7. Sign the header with RSA using the SLAK private key
8. Write the signed image (header + signature + payload)

USAGE
-----
    python sign.py -f <file> -n <name> -v <version> [-e] [-H]

    -f, --file      Path to the firmware binary to sign
    -n, --name      Image name (must match when verifying)
    -c, --chunk     Chunk ID (defaults to name)
    -v, --version   Version string in format "vAA.BB.CC.DD"
    -e, --encrypt   Encrypt the payload (optional)
    -H, --header    Only create header/signature, not full image

EXAMPLES
--------
    # Sign a firmware file without encryption
    python sign.py -f firmware.bin -n "wm220" -v "v01.00.00.00"

    # Sign and encrypt
    python sign.py -f firmware.bin -n "wm220" -v "v01.00.00.00" -e

OUTPUT
------
Creates a .sig file containing:
- 224-byte header (includes 32-byte chunk descriptor)
- 256-byte RSA signature
- Payload data (optionally encrypted, padded to 32-byte boundary)

The output file can be verified with:
    ./og_verify -n <name> -o decrypted.bin input.bin.sig

KEYS
----
This script uses the SLAK/SLEK key pair, which is included in og_verify.
These are NOT DJI's production keys - firmware signed with this script
can only be verified by og_verify, not by DJI's official tools.

Author: Jan Dumon <jan@crossbar.net>
License: GPL-3.0
"""

# Copyright (C) 2018  Jan Dumon <jan@crossbar.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# =============================================================================
# IMPORTS
# =============================================================================
import sys
import argparse
import os
import hashlib
import binascii
import datetime
import re
from Crypto.Cipher import AES          # AES encryption
from Crypto.PublicKey import RSA       # RSA key handling
from Crypto.Signature import PKCS1_v1_5  # PKCS#1 v1.5 signature scheme
from Crypto.Hash import SHA256         # SHA-256 hashing
from ctypes import *                   # C-compatible structures

# =============================================================================
# CRYPTOGRAPHIC KEYS
# =============================================================================

# SLEK - Slack Encryption Key
# This 16-byte AES key is used to encrypt the scramble key in the header.
# It must match the SLEK in verify.c for decryption to work.
SLEK = bytes([ 0x56, 0x79, 0x6C, 0x0E, 0xEE, 0x0F, 0x38, 0x05, 0x20, 0xE0, 0xBE, 0x70, 0xF2, 0x77, 0xD9, 0x0B ])

# SLAK - Slack Authentication Key (RSA Private Key)
# This is the RSA-2048 private key used to sign the header.
# The corresponding public key is embedded in verify.c.
# 
# SECURITY NOTE: This private key is intentionally included for
# educational purposes. In a real security system, the private key
# would never be distributed.
SLAK = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7AF5tZo4gtcUG
n//Vmk8XnDn2LadzEjZhTbs9h0X674aBqsri+EXPU+oBvpNvoyeisfX0Sckcg2xI
D6CUQJeUD4PijT9tyhis2PRU40xEK7snEecAK25PMo12eHtFYZN8eZVeySmnlNyU
bytlUrXEfRXXKzYq+cHVlOS2IQo2OXptWB4Ovd05C4fgi4DFblIBVjE/HzW6WJCP
IDf53bnzxXW0ZTH2QGdnQVe0uYT5Bvjp8IU3HRSy1pLZ35u9f+kVLnLpRRhlHOmt
xipIl1kxSGGkBkJJB76HdtcoOJC/O95Fl/qxSKzHjlg7Ku/gcUxmMZfvBi6Qih78
krJW0A+zAgMBAAECggEBALYZbtqj8qWBvGJuLkiIYprARGUpIhXZV2E7u6j38Lqi
w13Dvpx1Xi2+LnMSbSpaO/+fwr3nmFMO28P0i8+ycqj4ztov5+N22L6A6rU7Popn
93DdaxBsOpgex0jlnEz87w1YrI9H3ytUt9RHyX96ooy7rigA6VfCLPJacrm0xOf1
OIoJeMnGTeMSQlAFR+JzU5qdHHTcWi1WFNekzBgmxIXp6zZUkep/9+mxD7V8kGT2
MsJ/6IICe4euHA9lCpctYOPEs48yZBDljQfKD5FxVMUWBbXOhoCff99HeuW/4uVj
AO2mFp293nnGIV0Ya5PyDtGd+w/n8kcehFcfbfTvzZkCgYEA4woDn+WBXCdAfxzP
yUnMXEHB6189R9FTzoDwv7q3K48gH7ptJo9gq0+eycrMjlIGRiIkgyuukXD4FHvk
kkYoQ51Xgvo6eTpADu1CffwvyTi/WBuaYqIBH/HMUvFOLZu/jmSEsusXMTDmZxb+
Wpox17h1qMtNlyIqOBLyHcmTsy8CgYEA0trrk6kwmZC2IjMLswX9uSc5t3CYuN6V
g8OsES/68jmJxPYZTj0UidXms5P+V1LauFZelBcLaQjUSSmh1S95qYwM5ooi5bjJ
HnVH/aaIJlKH2MBqMAkBx6EtXqzo/yqyyfEZvt8naM8OnqrKrvxUCfdVx0yf7M7v
wECxxcgOGr0CgYBo198En781BwtJp8xsb5/nmpYqUzjBSXEiE3kZkOe1Pcrf2/87
p0pE0efJ19TOhCJRkMK7sBhVIY3uJ6hNxAgj8SzQVy1ZfgTG39msxCBtE7+IuHZ6
xcUvM0Hfq38moJ286747wURcevBq+rtKq5oIvC3ZXMjf2e8VJeqYxtVmEQKBgAhf
75lmz+pZiBJlqqJKq6AuAanajAZTuOaJ4AyytinmxSUQjULBRE6RM1+QkjqPrOZD
b/A71hUu55ecUrQv9YoZaO3DMM2lAD/4coqNkbzL7F9cjRspUGvIaA/pmDuCS6Wf
sOEW5e7QwojkybYXiZL3wu1uiq+SLI2bRDRR1NWVAoGANAp7zUGZXc1TppEAXhdx
jlzAas7J21vSgjyyY0lM3wHLwXlQLjzl3PgIAcHEyFGH1Vo0w9d1dPRSz81VSlBJ
vzP8A7eBQVSGj/N5GXvARxUswtD0vQrJ3Ys0bDSVoiG4uLoEFihIN0y5Ln+6LZJQ
RwjPBAdCSsU/99luMlK77z0=
-----END PRIVATE KEY-----"""

# =============================================================================
# DJI IMAGE STRUCTURES
# =============================================================================

class ImageHeader(LittleEndianStructure):
    """
    DJI firmware image header structure.
    
    This structure mirrors the dji_image_header_t in verify.c.
    All multi-byte fields are little-endian (ARM processor format).
    
    Total size: 192 bytes (not including chunk descriptors)
    
    Fields:
        magic_num: Must be "IM*H" (4 bytes)
        header_version: Header format version, typically 1
        size: Total image size (header + signature + payload)
        header_size: Size of header + chunk descriptors
        signature_size: RSA signature size (256 for RSA-2048)
        payload_size: Size of the payload data
        target_size: Expected size after decompression
        auth_alg: Authentication algorithm (1 = RSA-SHA256)
        auth_key: Key ID for signature ("SLAK" for us)
        enc_key: Key ID for encryption ("SLEK" for us)
        scram_key: Encrypted AES key for payload
        name: Image name (null-terminated string)
        version: Firmware version (4 bytes, BCD)
        date: Build date (BCD format: YYYYMMDD)
        chunk_num: Number of chunks (typically 1)
        payload_digest: SHA-256 hash of payload
    """
    _pack_ = 1
    _fields_ = [('magic_num', c_char * 4),          #0
                ('header_version', c_uint),         #4
                ('size', c_uint),                   #8
                ('reserved', c_char * 4),           #12
                ('header_size', c_uint),            #16
                ('signature_size', c_uint),         #20
                ('payload_size', c_uint),           #24
                ('target_size', c_uint),            #28
                ('os', c_ubyte),                    #32
                ('arch', c_ubyte),                  #33
                ('compression', c_ubyte),           #34
                ('anti_version', c_ubyte),          #35
                ('auth_alg', c_uint),               #36
                ('auth_key', c_char * 4),           #40
                ('enc_key', c_char * 4),            #44
                ('scram_key', c_ubyte * 16),        #48
                ('name', c_char * 32),              #64
                ('type', c_uint),                   #96
                ('version', c_ubyte * 4),           #100
                ('date', c_uint),                   #104
                ('reserved2', c_uint * 5),          #108
                ('userdata', c_uint * 4),           #128
                ('entry', c_ulonglong),             #144
                ('reserved3', c_uint),              #152
                ('chunk_num', c_uint),              #156
                ('payload_digest', c_ubyte * 32)]   #160 end is 192


class ImageChunk(LittleEndianStructure):
    """
    DJI firmware chunk descriptor.
    
    Each chunk describes a segment of the payload data.
    Chunks allow a single firmware image to contain multiple
    components that load to different memory addresses.
    
    Fields:
        id: 4-character chunk identifier
        offset: Byte offset of this chunk within payload
        size: Size of the chunk data in bytes
        attrib: Chunk attributes (1 = cleartext/not encrypted)
        addr: Target memory address for loading
        reserved: Unused, must be 0
    """
    _pack_ = 1
    _fields_ = [('id', c_char * 4),                 #0
                ('offset', c_uint),                 #4
                ('size', c_uint),                   #8
                ('attrib', c_uint),                 #12
                ('addr', c_ulonglong),              #16
                ('reserved', c_ulonglong)]          #24 end is 32

# =============================================================================
# SIGNING FUNCTION
# =============================================================================

def sign(filename, name, chunk_id, version, encrypt, separate_header):
    """
    Sign a firmware file with DJI-compatible signature.
    
    This function creates a signed firmware image that can be verified
    by og_verify. The signing process:
    
    1. Read and pad the input file to AES block boundaries
    2. Create the image header with metadata
    3. Generate a random scramble key and encrypt it with SLEK
    4. Optionally encrypt the payload with the scramble key
    5. Compute SHA-256 digest of the payload
    6. Sign the header with SLAK using RSA-SHA256
    7. Write the complete signed image
    
    Args:
        filename (str): Path to the input binary file
        name (str): Image name (stored in header, used for verification)
        chunk_id (str): Chunk identifier (defaults to name if None)
        version (str): Version string in format "vAA.BB.CC.DD"
        encrypt (bool): Whether to AES-encrypt the payload
        separate_header (bool): Only output header+signature, not payload
    
    Returns:
        int: -1 on error, None on success
    
    Output:
        Creates filename.sig with the signed image
    """
    
    # Validate version string format (e.g., "v01.02.03.04")
    ver = re.search('^v(\d+).(\d+).(\d+).(\d+)$', version)
    if ver == None:
        print('ERROR: Wrong version string format (vAA.BB.CC.DD): ' + version)
        return -1

    # Use name as chunk_id if not specified
    if not chunk_id:
        chunk_id = name

    # Encryption with separate header not currently supported
    if encrypt and separate_header:
        print('ERROR: Creating a separate signature AND encrypt the file is currently not supported')
        return -1

    # Read the input file
    image_file = open(filename, "rb")
    image_data = image_file.read()
    image_file.close()

    # Calculate padding
    # AES works on 16-byte blocks, so we need to pad to a multiple of 16
    # Additionally, DJI pads to 32-byte boundaries
    pad_cnt = (AES.block_size - len(image_data) % AES.block_size) % AES.block_size
    padded_length = len(image_data) + pad_cnt
    pad32_cnt = padded_length % 32
    padded_length += pad32_cnt

    # =======================================================================
    # BUILD THE IMAGE HEADER
    # =======================================================================
    header = ImageHeader()
    header.magic_num = bytes("IM*H", "utf-8")  # Magic number identifying DJI images
    header.header_version = 1                   # Current header format version
    header.size = 224 + 256 + padded_length    # Total size: header(192+32) + sig + payload
    header.header_size = 224                    # 192-byte header + 32-byte chunk
    header.signature_size = 256                 # RSA-2048 signature = 256 bytes
    header.payload_size = padded_length
    header.target_size = 224 + 256 + padded_length
    header.auth_alg = 1                         # 1 = RSA-SHA256
    header.auth_key = bytes("SLAK", "utf-8")   # Use Slack authentication key
    header.enc_key = bytes("SLEK", "utf-8")    # Use Slack encryption key
    header.name = bytes(name, "utf-8")
    
    # Parse version string and store in little-endian order
    header.version[3] = int(ver.group(1))  # Major version
    header.version[2] = int(ver.group(2))  # Minor version
    header.version[1] = int(ver.group(3))  # Patch version
    header.version[0] = int(ver.group(4))  # Build version
    
    # Encode current date in BCD format (YYYYMMDD)
    n = datetime.datetime.now()
    header.date = ((n.year // 1000) << 28) | (((n.year % 1000) // 100) << 24) | (((n.year % 100) // 10) << 20) | ((n.year % 10) << 16) |\
                  ((n.month // 10) << 12) | ((n.month % 10) << 8) | ((n.day // 10) << 4) | (n.day % 10)
    header.chunk_num = 1

    # =======================================================================
    # SCRAMBLE KEY HANDLING
    # =======================================================================
    # Generate a random 16-byte scramble key for this image
    scram_key = os.urandom(16)
    
    # Encrypt the scramble key with SLEK using ECB mode
    # This is stored in the header so the verifier can decrypt the payload
    cipher = AES.new(SLEK, AES.MODE_ECB)
    header.scram_key = (c_ubyte * 16)(*list(cipher.encrypt(scram_key)))
    
    # Prepare CBC cipher with the scramble key for payload encryption
    # IV is all zeros (not ideal, but matches DJI's approach)
    cipher = AES.new(scram_key, AES.MODE_CBC, bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))

    # =======================================================================
    # CHUNK DESCRIPTOR
    # =======================================================================
    chunk = ImageChunk()
    chunk.id = bytes(chunk_id, "utf-8")
    chunk.size = len(image_data)  # Original size before padding

    # Open output file
    output_file = open(filename + ".sig", "wb")

    # =======================================================================
    # PAYLOAD PADDING AND ENCRYPTION
    # =======================================================================
    # Add padding bytes
    # For encrypted payloads, padding value = number of padding bytes (PKCS#7)
    # For unencrypted payloads, padding is zero bytes
    if encrypt:
        pad_byte = bytes(chr(pad_cnt), "utf-8")
    else:
        pad_byte = bytes(chr(0), "utf-8")

    for _ in range(pad_cnt):
        image_data += pad_byte

    # Encrypt payload if requested
    if encrypt:
        encrypted_data = cipher.encrypt(image_data)
    else:
        chunk.attrib = 1  # Set CLEAR flag - payload is not encrypted
        encrypted_data = image_data

    # Pad to 32-byte boundary with zeros
    for _ in range(pad32_cnt):
        encrypted_data += bytes(chr(0), "utf-8")
        
    # =======================================================================
    # COMPUTE PAYLOAD DIGEST
    # =======================================================================
    # SHA-256 hash of the (possibly encrypted) payload for integrity
    digest = SHA256.new()
    digest.update(encrypted_data)
    header.payload_digest = (c_ubyte * 32)(*list(digest.digest()))

    # =======================================================================
    # RSA SIGNATURE
    # =======================================================================
    # Sign the header (including chunk descriptor) with the SLAK private key
    # The signature covers the header only, not the payload
    key = RSA.importKey(SLAK)
    signer = PKCS1_v1_5.new(key)
    digest = SHA256.new()
    digest.update(header)
    digest.update(chunk)

    # =======================================================================
    # WRITE OUTPUT
    # =======================================================================
    output_file.write(header)
    output_file.write(chunk)
    output_file.write(signer.sign(digest))

    # Write payload unless separate_header mode
    if not separate_header:
        output_file.write(encrypted_data)

    output_file.close()

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='File to sign.')
    parser.add_argument('-n', '--name', required=True, help='Name of the signed file.')
    parser.add_argument('-c', '--chunk', help='Name of the chunk. If omitted, <name> will be used.')
    parser.add_argument('-v', '--version', required=True, help='Version string in the form "vAA.BB.CC.DD"')
    parser.add_argument('-e', '--encrypt', default=False, action='store_true', help='Encrypt the file')
    parser.add_argument('-H', '--header', default=False, action='store_true', help='Only create the signature header')
    args = parser.parse_args()

    sign(args.file, args.name, args.chunk, args.version, args.encrypt, args.header)

# vim: expandtab:ts=4:sw=4
