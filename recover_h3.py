#!/usr/bin/env python3

import hashlib
import math
import os
import struct
import sys
import titlekeytools
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def parse_tmd(tmdfile):
    title_id = b''
    contents = []
    content_count = 0
    with open(tmdfile, 'rb') as tmd:
        tmd.seek(0x18C)
        title_id = tmd.read(8).hex()

        tmd.seek(0x1DE)
        content_count = struct.unpack('>H', tmd.read(2))[0]

        for c in range(content_count):
            tmd.seek(0xB04 + (0x30 * c))
            content_id = tmd.read(0x4).hex()
            
            # 0x2001 0x2003 or 0x6003; 0x2001 does not use .h3 files
            tmd.seek(0xB0A + (0x30 * c))
            content_type = struct.unpack('>H', tmd.read(2))[0]

            tmd.seek(0xB14 + (0x30 * c))
            content_hash = tmd.read(0x14)
            
            contents.append([content_id, content_type, content_hash])
    return title_id, contents

if __name__ == '__main__':
    if len(sys.argv) == 1:
        sys.exit('Usage: recover_h3.py <tmdfile>')
    tmdfile = sys.argv[1]
    if not os.path.isfile(sys.argv[1]):
        sys.exit('%s not found. Exiting' % tmdfile) 
    title_id, contents = parse_tmd(tmdfile)
    print('Title ID:               ' + title_id.upper())
    decrypted_titlekey = titlekeytools.derive(title_id, 'mypass')
    print('Decrypted Title Key     ' + decrypted_titlekey.hex().upper())
    extension = '.app' if os.path.isfile(contents[0][0] + '.app') else ''
    for c in contents:
        if c[1] & 2:
            if not os.path.isfile(c[0] + extension):
                print('Missing %s. Skipping to next file.' % c[0] + extension)
                continue
            h3_hashcount = math.ceil(os.path.getsize(c[0] + extension) / (0x10000*0x10**3)) # 1 hash per 256 MB
            outfile = c[0] + '.h3'
            with open(c[0] + extension, 'rb') as contentfile, open(outfile, 'wb') as h3file:
                for h in range(1, h3_hashcount+1):
                    cipher_hash_tree = Cipher(algorithms.AES(decrypted_titlekey), modes.CBC(bytes(16)), backend=default_backend()).decryptor()
                    hash_tree = cipher_hash_tree.update(contentfile.read(0x400)) + cipher_hash_tree.finalize()
                    check = hash_tree[0x140:0x280]
                    gen = hash_tree[0x280:0x3c0]
                    if hashlib.sha1(check).digest() != gen[:0x14]:
                        print('Decode Error! Data corruption or invalid Titlekey.')
                        print('Skipping %s' % outfile)
                        h3file.close()
                        os.remove(outfile)
                        break
                    h3part = hashlib.sha1(gen).digest()
                    h3file.write(h3part)
                    contentfile.seek(h * (0x10000*0x10**3))
            if os.path.exists(outfile):
                with open(outfile, 'rb') as h3file:
                    if hashlib.sha1(h3file.read()).digest() == c[2]:
                        print('Successfully created \'%s\'' % outfile)
                    else:
                        print('Error creating %s. Hash does not match. Corrupt tmd file?' %outfile)
