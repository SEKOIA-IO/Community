import re
import sys
import base64
import argparse
from typing import Set

try:
    import r2pipe
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    sys.exit(
        "Error missing import, "
        "r2pipe and/or cryptography dependencies might "
        "not be installed, please install them with: "
        "`pip install r2pipe==1.6.5 cryptography==3.3.2`"
    )

REG_VALID_URI = re.compile(r"https?://\S+")


def valid_uri(c2: str) -> bool:
    """Validate that Command and Control extracted value
    is a valid URI."""

    return REG_VALID_URI.match(c2)


def decrypt_rc4(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt RC4 encrypt data"""

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    cleartext = decryptor.update(ciphertext)

    return cleartext


def deobfuscate_c2(input_string: str, rc4_key: bytes) -> str:
    """base64 decode the input string and decrypt its content with
    the RC4 key given in parameters."""

    return decrypt_rc4(rc4_key, base64.b64decode(input_string))


def get_string(r2, r2_str: str) -> str:
    """Radare2 get string at given offset."""

    return r2.cmd(f"ps @ {r2_str}")


def main(filepath: str) -> Set[str]:

    print(
        f"Attempt to extract configuration of raccoon stealer v2 sample: `{filepath}`"
    )
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")
    r2.cmd("fs symbols; f")

    key = b""
    C2s = set()
    entry0 = r2.cmd("pds @ entry0").split("\n")

    for instruct in map(lambda x: x.split(), entry0):
        if not instruct:
            continue
        if instruct[-1].strip().startswith("str."):
            if not key:
                key = instruct[-1].strip().replace("str.", "")
                key = key.encode()
                print("Found the rc4 key: ", key)
            else:
                try:
                    string = get_string(r2, instruct[-1].strip())
                    c2 = deobfuscate_c2(string, key)
                    c2 = c2.decode()
                except Exception:
                    # error during deobfuscate process
                    pass
                else:
                    if valid_uri(c2):
                        C2s.add(c2)

    return C2s


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Raccoon v2 configuration extractor",
        description="Extract the list of C2 addresses" "for raccoon v2 stealer",
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Path to the samples to extract its configuration",
        required=True,
    )

    args = parser.parse_args()

    c2s = main(args.file)
    for idx, c2 in enumerate(c2s):
        print(f"{idx + 1}) Command and Control: {c2}")
