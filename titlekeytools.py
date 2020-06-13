# Generates valid _decrypted_ Title keys from Title IDs for 3DS, DSi, Wii, WiiU

import hashlib
import ctypes

def _secret(start, l): # always returns fd040105060b111c2d49
    ret = ""
    add = start + l
    for i in range(l):
        start = ctypes.c_uint64(start).value
        ret += hex(start)[-2:] if start >= 0x10 else '0'+hex(start)[-1]
        next = start + add
        add = start
        start = next
    return ret

def _mungetid(tid):
    tid = tid.lstrip('0')
    if (len(tid) % 2) == 1:
        return '0' + tid
    return tid

def derive(tid, pwd):
    sec = _secret(-3, 10)
    salt = bytes.fromhex(hashlib.md5(bytes.fromhex(sec + _mungetid(tid))).hexdigest())
    return hashlib.pbkdf2_hmac("sha1", pwd.encode(), salt , 20, 16) # (hash_name, password, salt, iterations, dklen)