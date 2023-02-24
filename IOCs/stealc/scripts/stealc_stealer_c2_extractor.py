from base64 import b64decode
from pefile import PE, SectionStructure
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class Stealc:

    """Stealc configuration"""

    rc4_key: bytes = b""
    base_url: str = ""
    endpoint_url: str = ""
    dlls_directory: str = ""

    def __str__(self):
        out = f"Stealc RC4 key: {self.rc4_key}\n"
        out += f"SteaC Command and Control:\n"
        out += f"\t- {''.join([self.base_url, self.endpoint_url])}\n"
        out += f"\t- {''.join([self.base_url, self.dlls_directory])}\n"
        return out

    def rc4_decrypt(self, data: bytes) -> bytes:
        """decrypt RC4 data with the provided key."""

        algorithm = algorithms.ARC4(self.rc4_key)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(data)


def get_section(pe: PE, section_name: str) -> SectionStructure:
    """return section by name, if not found raise KeyError exception."""

    for section in filter(
        lambda x: x.Name.startswith(section_name.encode()), pe.sections
    ):
        return section

    available_sections = ", ".join(
        [_sec.Name.replace(b"\x00", b"").decode() for _sec in pe.sections]
    )
    raise KeyError(
        f"{section_name} not found in the PE, available sections: {available_sections}"
    )


def get_rdata(pe_path: str) -> SectionStructure:
    """Extract Stealc radata section"""

    pe = PE(pe_path)
    section_rdata = get_section(pe, ".rdata")
    return section_rdata


def is_valid_string(data: bytes) -> bool:
    return True if all(map(lambda x: x >= 43 and x <= 122, data)) else False


def search_Command_and_Control(stealc: Stealc, rdata_section: SectionStructure):
    """
    Search two types of strings in rdata section of Stealc:
    1. The RC4 key which is 20 bytes long;
    2. Strings matching the way Stealc stores its C2 configuration (these strings are decoded (base64 decode + RC4 decryption),
       This works for the Stealc version at least until 15 Feb 2023 but could change in new versions...
        2.1 base url (`http://something...` or `https://something...`)
        2.2 endpoint which ends with `.php`
        2.3 DLLs directory starts and ends with `/` (eg: `/something_random/`)
    """

    for string in filter(
        lambda x: x and is_valid_string(x), rdata_section.get_data().split(b"\x00" * 2)
    ):
        if len(string) == 20 and not stealc.rc4_key:
            # Hopefully the RC4 key is stored as the beginning of the rdata section
            stealc.rc4_key = string
            print(f"[+] RC4 key found: {stealc.rc4_key}")
        if stealc.rc4_key and string != stealc.rc4_key:
            try:
                cleartext = stealc.rc4_decrypt(b64decode(string))
                # print(f"{string.decode():<40} {cleartext}")
                if cleartext.startswith(b"http://") or cleartext.startswith(
                    b"https://"
                ):
                    print(f"[+] Found StealC Command and Control")
                    stealc.base_url = cleartext.decode()
                elif cleartext.startswith(b"/") and cleartext.endswith(b"/"):
                    print(f"[+] Found DLLs URL directory name")
                    stealc.dlls_directory = cleartext.decode()
                elif cleartext.endswith(b".php"):
                    print(f"[+] Found StealC endpoint")
                    stealc.endpoint_url = cleartext.decode()

            except Exception:
                pass


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            f"not enough parameter, please provide as argument the path to stealc sample."
        )
    stealc = Stealc()
    rdata = get_rdata(sys.argv[1])
    search_Command_and_Control(stealc, rdata)
    print(stealc)
