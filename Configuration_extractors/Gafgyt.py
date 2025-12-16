from io import BytesIO
import logging
import lief
from lief.ELF import ARCH, Header
import struct
from typing import List, Optional
from maco.extractor import Extractor
from maco.model import ExtractorModel
from maco.model import CategoryEnum
from maco.model import ConnUsageEnum
from maco import yara
from collections import namedtuple
from ipaddress import IPv4Address, AddressValueError


CommandAndControl = namedtuple("CommandAndControl", ["ip", "port"])


def check_ip(ioc: str) -> bool:
    """Use the built-in library ipadress to
    validate that the provided parameter `ioc`
    is a valid IPv4 address"""

    try:
        IPv4Address(ioc)
    except AddressValueError:
        return False
    else:
        return True


class ConfigExtractor:
    SUPPORTED_ARCHS = {ARCH.X86_64, ARCH.ARM, ARCH.I386, ARCH.SH, ARCH.MIPS}

    def __init__(self, elf: lief.ELF.Binary):
        self.elf = elf
        self.arch = elf.header.machine_type
        self.indian = (
            "big"
            if elf.header.identity_data == lief.ELF.Header.ELF_DATA.MSB
            else "little"
        )

    def find_symbol(self) -> Optional[int]:
        """Locate the symbol 'commServer' and return its virtual address."""
        for sym in self.elf.symbols:
            if sym.name == "commServer":
                return sym.value
        logging.error("commServer symbol not found")
        return None

    def extract_addr(self, comm_addr: int) -> Optional[int]:
        """Extract the pointer stored at commServer."""
        try:
            data = self.elf.get_content_from_virtual_address(comm_addr, 4)
            if len(data) != 4:
                raise ValueError("Unexpected size for commServer pointer")
            return int.from_bytes(data, byteorder=self.indian)
        except Exception as e:
            logging.error(f"error on c2 address extraction : {e}")
            return None

    def extract_c2(self, inst_addr: int) -> Optional[str]:
        """Extract C2 string located at inst_addr."""
        try:
            content = self.elf.get_content_from_virtual_address(inst_addr, 40)
            return bytes(content).split(b"\x00", 1)[0].decode("utf-8")
        except Exception as e:
            logging.error(f"c2 extraction error : {e}")
            return None

    def parse_c2(self, raw_data: str) -> Optional[CommandAndControl]:
        """Parse <ip>:<port> format."""
        try:
            ip, port_str = raw_data.split(":")
            return CommandAndControl(ip=ip, port=int(port_str))
        except Exception as e:
            logging.error(f"c2 parsing error : {e}")
            return None

    def run(self) -> Optional[CommandAndControl]:
        if self.arch not in self.SUPPORTED_ARCHS:
            raise ValueError(f"Unsupported architecture : {self.arch}")

        comm_addr = self.find_symbol()
        if comm_addr is None:
            logging.error("Missing commServer Addr")
            return None

        c2_addr = self.extract_addr(comm_addr)
        if c2_addr is None:
            logging.error("no c2 found")
            return None

        raw_c2 = self.extract_c2(c2_addr)
        if not raw_c2:
            logging.error("c2 extraction failed or empty")
            return None

        return self.parse_c2(raw_c2)


class Gafgyt(Extractor):
    author = "Sekoia.io"
    last_modified = "28-03-2025"
    category = [CategoryEnum.bot, CategoryEnum.ddos]
    family = "Gafgyt"
    yara_rule = """
    rule Gafgyt
    {
        meta:
            author = "Sekoia IO"
            malware = "Gafgyt"
            description = "Catch Gafgyt malware on common instruction and pattern"
            hash = "bc0e5283242cb483a4b22ab26b7206bd"
            hash = "06e67cc210daff5323aa18fab7b1cc92"
            hash = "a7c20be31ae57de59b15e09c12342812"
            hash = "ec41d70c25a970b437752df86d45ca2f"
            hash = "f318180361a32856f9b3827f96baf8ad"
            hash = "b0100f50a771e7ce719a6565235289ec"
        strings:
            $s0 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }
            $s1 = "commServer" ascii
            $s2 = "mainCommSock" ascii
            $s3 = "currentServer" ascii
        condition:
            uint32be(0) == 0x7f454c46 and all of them and filesize > 40KB and filesize < 160KB
    }

    """

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[ExtractorModel]:
        data = stream.read()

        if not data:
            logging.error("no data")
            return None

        for hit in matches:
            if any(filter(lambda hit: hit.rule.startswith("Gafgyt"), matches)):
                ret = ExtractorModel(
                    family=self.family, version="Linux", category=self.category
                )
                try:
                    elf = lief.parse(data)
                    config_extract = ConfigExtractor(elf)
                    c2 = config_extract.run()

                    if c2:
                        connection_kwargs = {
                            "server_port": c2.port,
                            "usage": ConnUsageEnum.c2,
                        }
                        if check_ip(c2.ip):
                            connection_kwargs["server_ip"] = c2.ip
                        else:
                            connection_kwargs["server_domain"] = data.c2
                        ret.tcp.append(ret.Connection(**connection_kwargs))
                    else:
                        logging.error("no C2 extraction")

                    return ret

                except Exception as e:
                    logging.error(f"error during extraction: {e}")
                    return None

            else:
                logging.error("no Yara match")
                return None
