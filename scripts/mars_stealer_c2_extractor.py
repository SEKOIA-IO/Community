import sys
import re
import json
import base64
import argparse
import logging
from typing import Any, List, Tuple
from collections import namedtuple

try:
    import r2pipe
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    sys.exit(
        "Error missing import, "
        "r2pipe and/or cryptography dependencies might "
        "not be installed, please installed them with: "
        "`pip install r2pipe==1.6.5 cryptography==3.3.2`"
    )


Section = namedtuple(
    "Section", ["name", "id", "paddr", "size", "vaddr", "vsize", "perm"]
)


def unxor(string: List[Any], key: List[Any]) -> str:
    """Method to unxor obfuscated data from llcppc section"""

    unxored = ""

    for c1, c2 in zip(string, key):
        unxored += chr(c1 ^ c2)

    return unxored


def decrypt_rc4(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt RC4 encrypt data"""

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    cleartext = decryptor.update(ciphertext)

    return cleartext


def map_sections(r2: r2pipe.open_sync.open) -> list:
    """Parse section from r2pipe output"""

    raw_sections = r2.cmd("iS")

    sections = []
    for _section in map(str.split, raw_sections.split("\n")[4:]):
        if not _section:
            break
        section = Section(
            _section[-1].lower(),
            int(_section[0]),
            int(_section[1], 16),
            int(_section[2], 16),
            int(_section[3], 16),
            int(_section[4], 16),
            _section[5],
        )
        sections.append(section)

    return sections


def analyze_file(filepath: str) -> r2pipe.open_sync.open:
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa;aac")
    return r2


def locate_entrypoint(r2: r2pipe.open_sync.open, sections: list) -> str:
    """return the section where entrypoint is located,
    return section name otherwise raise ValueError Exception."""

    ie = r2.cmd("ie")
    ie = int(ie.split("\n")[1].split()[0].split("=")[1], 16)  # noqa

    for section in sections:
        if ie >= section.vaddr and ie < (section.vaddr + section.vsize):
            logging.debug(f"IE in section: {section.name}")
            return section.name

    raise ValueError("entrypoint not contains in known sections")


def get_base_addr(r2: r2pipe.open_sync.open) -> int:
    """return base address of the PE"""

    output = json.loads(r2.cmd("ij"))
    return output.get("bin").get("baddr")


def get_c2_from_llcppc(r2: r2pipe.open_sync.open, sections: list) -> Tuple[str, str]:
    """Read C2 from LLCPPC section (unxored)"""

    base_addr_llcppc = list(filter(lambda x: x.name == "llcppc", sections))
    if not base_addr_llcppc:
        return "", ""
    base_addr_llcppc = base_addr_llcppc[0].vaddr
    output = r2.cmd(f"s {base_addr_llcppc}; px 1000")

    datas: list = [[]]  # list of list
    index = 0
    for line in output.split("\n")[1:]:
        data = "".join(line.split()[1:9])
        if not data.startswith("0000"):
            datas[index].append("".join(data))
        else:
            index += 1
            datas.append([])

    if not datas:
        logging.debug("no secret found in LLCPPC section")

    propre = []
    for i in filter(lambda x: x, datas):
        propre.append("".join(i))

    propre.pop(0)
    c2_ip = propre.pop(0)
    c2_ip = "".join(c2_ip.split("00"))
    c2_url = propre.pop(0)
    c2_url = "".join(c2_url.split("00"))

    xor_key = propre.pop(0)
    c2_ip_xored = [int(c2_ip[i : i + 2], 16) for i in range(0, len(c2_ip), 2)]
    c2_url_xored = [int(c2_url[i : i + 2], 16) for i in range(0, len(c2_url), 2)]
    xor_key = [int(xor_key[i : i + 2], 16) for i in range(0, len(xor_key), 2)]  # noqa

    if ord(".") in c2_ip_xored:
        logging.warning("no obfuscation")
        c2_ip = "".join(map(chr, c2_ip_xored))
        c2_url = "".join(map(chr, c2_url_xored))
    else:
        c2_ip = unxor(c2_ip_xored, xor_key)
        c2_url = unxor(c2_url_xored, xor_key)

    return c2_ip, c2_url


def get_llcppc_rc4_key(
    r2: r2pipe.open_sync.open, sections: list, base_adddr: int
) -> bytes:

    rdata = list(filter(lambda x: x.name == ".rdata", sections))[0]

    out = r2.cmd(f"s {rdata.vaddr}; ps 300")
    for string in out.split("\\x00\\x00"):
        if len(string) == 20:
            rc4_key = string
            break

    return rc4_key.encode()


def get_string(r2: r2pipe.open_sync.open, baddr: int, offset: int) -> str:
    return r2.cmd(f"ps @{baddr + offset}")


def get_c2_llcppc_rc4(r2: r2pipe.open_sync.open, sections: list) -> str:

    baddr = get_base_addr(r2)
    rc4_key = get_llcppc_rc4_key(r2, sections, baddr)
    logging.debug(f"RC4 key is: {rc4_key}")

    llcppc_vaddr = list(filter(lambda x: x.name == "llcppc", sections))[0].vaddr

    analyse_llcppc = r2.cmd(f"s {llcppc_vaddr}; pd").split("\n")

    c2 = []

    for instruction in analyse_llcppc:
        if "lea eax" in instruction:
            re_addr = re.search(r"(?P<addr>0x[a-f0-9]{4,})(\])", instruction)
            if re_addr is None:
                continue
            string_offset = int(re_addr.group("addr")[2:], 16)
            obfuscated_str = get_string(r2, baddr, string_offset)
            obfuscated_str = obfuscated_str.replace("\n", "")
            cleartext = decrypt_rc4(rc4_key, base64.b64decode(obfuscated_str))
            c2.append(cleartext.decode())

    return c2


def get_obfuscated_string_range_addr(r2: r2pipe.open_sync.open) -> tuple:

    symbols = r2.cmd("fs symbols; f")
    function = "entry0"

    if "main" in symbols:
        function = "main"

    analyse_entry0 = r2.cmd(f"s {function}; pdf").split("\n")
    count = 0
    for instruction in analyse_entry0:
        if "call fcn." in instruction:
            count += 1
            if count == 7:
                string_list_function_addr_index = instruction.find("fcn.")
                string_list_function_addr = instruction[
                    string_list_function_addr_index:
                ]
                break

    if count != 7:
        raise ValueError("cannot find function")

    analyze_string_function = r2.cmd(f"s {string_list_function_addr}; pdf").split("\n")
    start_addr, end_addr = 0, 0

    for instruction in analyze_string_function:
        re_addr = None
        if "push str." in instruction:
            re_addr = re.search(r"(; )(?P<addr>0x[a-f0-9]{4,})", instruction)
        if "push 0x" in instruction:
            re_addr = re.search(r"(push )(?P<addr>0x[a-f0-9]{4,})", instruction)
        if re_addr:
            if start_addr == 0:
                start_addr = re_addr.group("addr")

            # last match
            end_addr = re_addr.group("addr")

    return int(start_addr[2:], 16), int(end_addr[2:], 16)


def get_rc4_key(r2: r2pipe.open_sync.open) -> bytes:
    symbols = r2.cmd("fs symbols; f")
    function = "entry0"

    if "main" in symbols:
        function = "main"

    analyse_entry0 = r2.cmd(f"s {function}; pdf").split("\n")
    for instruction in analyse_entry0:
        if "call fcn." in instruction:
            string_list_function_addr_index = instruction.find("fcn.")
            string_list_function_addr = instruction[string_list_function_addr_index:]
            break

    strings_list_function = r2.cmd(f"s {string_list_function_addr}; pdf").split("\n")
    for instruction in strings_list_function:
        if "mov dword [" in instruction:
            re_addr = re.search(r"(, )(?P<addr>0x[a-f0-9]{4,})", instruction)
            if re_addr:
                addr = re_addr.group("addr")
                break

    rc4_key = r2.cmd(f"s {addr}; pr 20")
    return rc4_key


def get_c2_from_text(r2: r2pipe.open_sync.open) -> str:

    start_addr, end_addr = get_obfuscated_string_range_addr(r2)
    rc4_key = get_rc4_key(r2)

    ciphertexts = r2.cmd(f"s {start_addr}; psx {end_addr-start_addr}")
    ciphertexts = ciphertexts.split("\\x00\\x00\\x00\\x00")
    cleartexts = []

    logging.debug(f"RC4 key is: {rc4_key}")
    for ciphertext in ciphertexts:
        cleartext = decrypt_rc4(rc4_key.encode(), base64.b64decode(ciphertext))
        try:
            cleartext = cleartext.decode()  # noqa
        except Exception:
            logging.error(f"failed to decrypt {cleartext}")
        finally:
            cleartexts.append(cleartext)

    return cleartexts[1:3]


def get_c2(r2: r2pipe.open_sync.open, sections: list) -> str:

    c2 = None

    if not any(map(lambda x: "text" in x.name, sections)):
        logging.critical("no .text section found")
        return ""

    if any(map(lambda x: "llcppc" in x.name, sections)):
        if any(map(lambda x: ".vmp" in x.name, sections)):
            logging.error("Unknow method to get C2 over VMProtect")
            return ""
        ie_section = locate_entrypoint(r2, sections)
        if ie_section == "llcppc":
            logging.debug(f"Unxored C2 from {ie_section.upper()} section")
            c2 = get_c2_from_llcppc(r2, sections)
        else:
            logging.debug("Decrypt(rc4) C2 from .LLCPPC section")
            c2 = get_c2_llcppc_rc4(r2, sections)
    else:
        logging.debug("Decrypt (rc4) C2 from .text section")
        c2 = get_c2_from_text(r2)

    return c2


def extract(filepath: str) -> str:

    logging.info(f"Analyze {filepath}")
    r2 = analyze_file(filepath)
    sections = map_sections(r2)

    try:
        c2 = get_c2(r2, sections)
    except Exception as err:
        logging.info(f"Error getting c2: {err}")
        return ""

    if c2 is None or c2 == ["", ""] or not c2:
        return ""

    c2 = list(c2)

    if "http" not in c2[0]:
        if not c2[1].startswith("/"):
            c2[1] = f"/{c2[1]}"
        c2 = "".join(c2)

        if not c2.startswith("http://") and not c2.startswith("https://"):
            for schema in ["http://", "https://"]:
                logging.info(f"C2 is: {schema}{c2}")
    else:
        if len(c2) > 2:
            if not c2[2].startswith("/"):
                c2[2] = f"/{c2[2]}"
        c2 = "".join(c2)
        logging.info(f"C2 is: {c2}")

    return c2


def analyze_all(directory_name: str):
    """Start Analyze on all sample of a directory"""

    from os import walk, path

    for _dir, subdirs, files in walk(directory_name):
        for _file in files:
            extract(path.join(_dir, _file))


if __name__ == "__main__":

    parser = argparse.ArgumentParser("Mars Stealer C2 configuration extractor")
    parser.add_argument(
        "-a",
        "--all",
        help="Directory name used to test extraction several samples",
        required=False,
        default=True,
        action="store_true",
    )
    parser.add_argument(
        "-d",
        "--directory",
        help="path to the directory that contains samples",
        required=False,
    )
    parser.add_argument(
        "-f", "--file", help="File path to the sample", required=False, type=str
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Activate verbose mode",
        default=False,
        action="store_true",
    )
    args = parser.parse_args()

    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s")
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if args.all and args.directory:
        analyze_all(args.directory)
    else:
        extract(args.file)
