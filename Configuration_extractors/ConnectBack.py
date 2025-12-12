import struct
from io import BytesIO
import re
import logging
from typing import List, Optional
from ipaddress import IPv4Address, AddressValueError
from maco.extractor import Extractor
from maco.model import ExtractorModel
from maco.model import CategoryEnum
from maco.model import ConnUsageEnum
from maco import yara

def check_ip(ioc: str) -> bool:
    """Use the built-in library ipadress to
    validate that the provided parameter `ioc`
    is a valid IPv4 address (it exclude local address)

    >>> assert check_ip('127.0.0.1') is False
    >>> assert check_ip('183.123.11.1') is True
    >>> assert check_ip('This is not an IP') is False"""

    try:
        IPv4Address(ioc)
    except AddressValueError:
        return False
    else:
        return True

class ConnectBack(Extractor):

    family = "ConnectBack"
    author = "Sekoia.io"
    last_modified = "30-01-2025"
    category = [CategoryEnum.backdoor]

    yara_rule = """
    rule ConnectBack_x64
    {
        meta:
            author = "Sekoia IO"
            malware = "ConnectBack"
            description = "Catch ConnectBack64 on common instruction and pattern"
            hash = "639b3e01d2d885f4a2b0c66d92c73957"
            hash = "8646ba08e924bbfb8cbcc70e17ff72c1"
            hash = "93d6a0a4e6ff89f4430ed4bd80e5fa71"
        strings:
            $syscall = { 0F 05 }
            $sock1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 } //syscall socket
            $sock2 = { 48 89 D6 4D 31 C9 6A 22 41 5A 6A 07 5A 0F 05 } //syscall connet

        condition:
            uint32(0)==0x464c457f and uint8(4) == 2 and filesize >= 250 and filesize <= 250 and #syscall == 6 and all of ($sock*)
    }

    rule ConnectBack_x86
    {
        meta:
            author = "Sekoia IO"
            malware = "ConnectBack"
            description = "Catch ConnectBack32 on common instruction and pattern"
            hash = "57d47068c6ec56834466859f273be2da"
            hash = "33e34d4cf0c3da2095f7a4419f6aade6"
        strings:
            $syscall = { CD 80 } // interrupt 0x80
            $sock = { 68 ?? ?? ?? ?? 68 02 00 ?? ?? ?? ?? ?? 66 } // 0x68 push ip and 0x68 push padding byte and 0x66 sys_connect

        condition:
            uint32(0)==0x464c457f and uint8(4) == 1 and filesize > 150 and filesize < 210 and $sock and #syscall >= 4 and #syscall <= 6
    }
    """

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[ExtractorModel]:
        data = stream.read()

        if not data:
            logging.error(f"no data")
            return None

        for hit in matches:
            if any(filter(lambda hit: hit.rule.startswith("ConnectBack"), matches)):
                c2: tuple = ()
                ret = ExtractorModel(family=self.family, version="Linux", category=self.category)
                try:
                    if matches[0].rule == "ConnectBack_x64":

                        pattern = b'\x48\xB9\x02\x00'
                        index = data.find(pattern)

                        if index != -1:
                            port_bytes = data[index + 4: index + 6]  # 2 octets pour le port
                            ip_bytes = data[index + 6: index + 10]   # 4 octets pour l'IP
                            port = struct.unpack(">H", port_bytes)[0] # postulat Big endian - x64
                            ip = ".".join(map(str, ip_bytes))
                            if check_ip(str(ip)):
                                c2 = (str(ip), str(port))

                    if matches[0].rule == "ConnectBack_x86":
                        raw_c2 = re.search(rb"(\x68)(?P<ipaddr>(..){2})(\x68\x02\x00)(?P<port>(..){1})", data) # 68 PUSH 4 octets IP 68 push 2 octets padding 2 octets port
                        if raw_c2:
                            raw_c2 = raw_c2.groupdict()
                            ip = IPv4Address(struct.unpack(">L", raw_c2.get('ipaddr'))[0])
                            port = struct.unpack(">h", raw_c2.get('port'))[0]

                            if check_ip(str(ip)):
                                c2 = (str(ip), str(port))

                    if c2:
                        ret.tcp.append(
                            ret.Connection(
                                server_ip=c2[0],
                                server_port=int(c2[1]),
                                usage=ConnUsageEnum.c2,
                            )
                        )

                    return ret
                except Exception as e:
                    logging.error(f"error during extraction: {e}")
                    return None

            else:
                return None
