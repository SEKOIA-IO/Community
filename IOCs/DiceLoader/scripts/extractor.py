import sys
import pefile
from typing import List


def get_data_section_virtualAddress(pe: pefile.PE) -> int:
    """Return the .data section of a PE file."""

    data_va: int = 0

    for section in pe.sections:
        if section.Name.startswith(b".data"):
            data_va = section.VirtualAddress
            break

    if not data_va:
        raise ValueError("cannot find .data section, extraction failed")

    return data_va


def xor(blob: bytes, key: bytes) -> bytes:
    """DiceLoader XOR operation"""

    cleartext = b""

    for index, value in enumerate(blob):
        cleartext += (value ^ key[index % len(key)]).to_bytes()

    return cleartext.split(b"\x00")[0]


def extract(filepath: str) -> List[str]:
    """Extract DiceLoader configuration:
    1. Find blobs for ip, port and the key at
       the beggining of the .data section
    2. Deobfuscate each blob
    3. Re-build the ip:port C2
    """

    pe = pefile.PE(filepath)
    data_va = get_data_section_virtualAddress(pe)

    blob_port = pe.get_data(rva=data_va, length=0xC0)
    key = pe.get_data(rva=data_va + 0xC0, length=0x1F)
    blob_c2 = pe.get_data(rva=data_va + 0xC0 + 0x1F + 0x1, length=0x100)

    grouper = lambda iterable, n: zip(*([iter(iterable)] * n))

    ip_addresses = xor(blob_c2, key).split(b"|")
    ports = [group[0] * 2**8 + group[1] for group in grouper(xor(blob_port, key), 2)]

    return [f"{ip.decode()}:{port}" for ip, port in zip(ip_addresses, ports)]


if __name__ == "__main__":
    print(extract(sys.argv[1]))
