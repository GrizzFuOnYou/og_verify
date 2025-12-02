#!/usr/bin/env python3
"""
DJI Firmware Package Configuration Patcher

This script updates a DJI firmware package configuration file (.cfg) after
you've modified and re-signed one of its component modules. DJI firmware
packages contain a .cfg file that lists all modules with their hashes,
sizes, and versions - this script updates those values to match a new .sig file.

PURPOSE
-------
When you modify a DJI firmware module and re-sign it with sign.py:
1. The file size changes
2. The MD5 hash changes  
3. The version might change

The .cfg file contains these values for each module, and the DJI update
process checks them. This script automatically updates the .cfg to match
your modified .sig file.

HOW IT WORKS
------------
1. Read the original .cfg file
2. Parse the .sig file header to extract name, version, and size
3. Compute MD5 hash of the complete .sig file
4. Find the matching <module> entry in the .cfg
5. Update the md5, size, version, and filename attributes
6. Output the modified .cfg to stdout

USAGE
-----
    python patch_cfg.py -c <cfg_file> -s <sig_file> > new_cfg.cfg

    -c, --cfg    Path to the original .cfg file
    -s, --sig    Path to the new .sig file

EXAMPLE
-------
    # After signing a modified module:
    python sign.py -f wm220_0801.bin -n wm220 -v v01.02.03.04
    
    # Update the config to match:
    python patch_cfg.py -c wm220_V01.03.0500.cfg -s wm220_0801.bin.sig > new.cfg

CFG FILE FORMAT
---------------
DJI .cfg files are XML-like with <module> entries like:

    <module id="0801" type="aa15" size="123456" md5="abc..." version="01.02.03.04">
        filename.bin.sig
    </module>

This script updates: md5, size, version, and the filename.

NOTE: This script outputs the modified config to stdout. Redirect to a file
to save the result.

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
import os
import re
import binascii
import argparse
from Crypto.Hash import MD5    # MD5 hashing for file integrity
from ctypes import *           # C-compatible structures

# =============================================================================
# DJI IMAGE STRUCTURES
# =============================================================================
# These structures mirror the ones in sign.py and verify.c

class ImageHeader(LittleEndianStructure):
    """
    DJI firmware image header structure.
    
    We parse this from the .sig file to extract version information.
    See sign.py for detailed field documentation.
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
    
    We parse this from the .sig file to get the chunk ID, which is used
    to match the module entry in the .cfg file.
    """
    _pack_ = 1
    _fields_ = [('id', c_char * 4),                 #0
                ('offset', c_uint),                 #4
                ('size', c_uint),                   #8
                ('attrib', c_uint),                 #12
                ('addr', c_ulonglong),              #16
                ('reserved', c_ulonglong)]          #24 end is 32

# =============================================================================
# PATCHING FUNCTION
# =============================================================================

def patch_cfg(cfg_file, module_file):
    """
    Patch a DJI config file with updated module information.
    
    Reads a .sig file to extract its metadata (chunk ID, version, size)
    and computes its MD5 hash. Then reads the .cfg file line by line,
    updating any <module> entry that matches the chunk ID and type.
    
    Args:
        cfg_file (str): Path to the original .cfg file
        module_file (str): Path to the new .sig file
    
    Output:
        Prints the modified .cfg to stdout
    
    The matching is done by:
    1. Extracting the chunk ID from the .sig file (e.g., "0801")
    2. Extracting the type number from the filename (e.g., "_aa15.pro" -> "aa15")
    3. Finding the <module> line with matching id and type attributes
    """
    cfg = open(cfg_file, "r")

    # Read the complete .sig file and compute its MD5 hash
    module_data = open(module_file, "rb").read()
    digest = MD5.new()
    digest.update(module_data)

    # Parse the header and chunk descriptor from the .sig file
    len_header = sizeof(ImageHeader)
    len_chunk = sizeof(ImageChunk)

    header = ImageHeader.from_buffer_copy(bytearray(module_data[0:len_header]))
    chunk  = ImageChunk.from_buffer_copy(bytearray(module_data[len_header:len_header + len_chunk]))

    # Get the chunk ID (e.g., "0801" for main firmware)
    name = chunk.id.decode()
    
    # Try to extract the type number from the filename
    # DJI filenames often include the type like "_aa15.pro"
    try:
        type_num = re.search('_..\d{2}\.pro' , module_file).group(0).split('.')[0][1:]
    except:
        type_num=""

    # Build version string from header bytes (e.g., "01.02.03.04")
    version = str(header.version[3]).zfill(2) + '.' + \
              str(header.version[2]).zfill(2) + '.' + \
              str(header.version[1]).zfill(2) + '.' + \
              str(header.version[0]).zfill(2)

    # Process each line of the config file
    for line in cfg:
        # Check if this line matches our module (by chunk ID and type)
        if line.find(' id="%s" ' % name) != -1 and line.find(' type="%s" ' % type_num) != -1:
            # Update the MD5 hash
            line = re.sub(' md5="[^"]*"', ' md5="%s"' % binascii.hexlify(digest.digest()).decode(), line)
            # Update the filename (content between > and </module>)
            line = re.sub('>[^<]*</module>', '>%s</module>' % os.path.basename(module_file), line)
            # Update the file size
            line = re.sub(' size="[^"]*"', ' size="%d"' % len(module_data), line)
            # Update the version
            line = re.sub(' version="[^"]*"', ' version="%s"' % version, line)
            print(line, end='')
        else:
            # Not our module - output unchanged
            print(line, end='')

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cfg', required=True, help='.cfg file to patch.')
    parser.add_argument('-s', '--sig', required=True, help='.sig file to update in the cfg file.')
    args = parser.parse_args()

    patch_cfg(args.cfg, args.sig)

# vim: expandtab:ts=4:sw=4
