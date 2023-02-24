from idaapi import *
from ida_bytes import *
from ida_name import *
from base64 import b64decode
from string import ascii_letters, digits
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def read_rdata(name: str) -> str:
    print(f"read_rdata: {name}")
    addr = get_name_ea_simple(name)
    size = get_max_strlit_length(addr, ida_nalt.STRENC_DEFAULT)
    return get_bytes(addr, size - 1)

def rc4_decrypt(key: bytes, data: bytes) -> bytes:

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def deobfuscate_string(base: int, end: int , KEY: bytes):
    ea = base
    size = 0
    clear = []
    addr = []

    while ea <= end:
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags):
            instr_str = idc.generate_disasm_line(ea, 1)
            instr_str = " ".join(instr_str.split())
            if instr_str.startswith("push offset a") or instr_str.startswith("mov dword ptr [esp], offset a"):
                value = instr_str.split("offset")[-1].split(';')[0].strip()
                value = read_rdata(value)
                clear.append(rc4_decrypt(KEY, b64decode(value)))
            elif instr_str.startswith("mov dword_"):
                temp = instr_str.replace("mov dword_", "")
                temp = temp.split()[0].replace(",","")
                addr = int(temp, 16)
                string = get_bytes(addr, size)
                cleartext = clear.pop(-1)
                cleartext = cleartext.decode()
                idc.set_cmt(ea, cleartext, 0)
                text = ""
                for c in cleartext:
                    if c in f"{ascii_letters}{digits}":
                        text += c
                    else:
                        text += "_"
                cleartext = f"str_{text}"
                print(f"replace dword_{addr:x} by `{cleartext}`")
                set_name(addr, cleartext)
        ea += 1
