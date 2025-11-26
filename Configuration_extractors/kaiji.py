from io import BytesIO
import re
import logging
import base64
from floss import strings
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

def extract_b64_and_decode(data: bytes) -> str:
    """
    If C2 is simply base64 encoded, it can be identified in the payload strings.
    The string is systematically placed after use ParseCertificate pattern
    Once decoded, it is of the form `c2:port|(odk)/*-`
    Exemple with payload 2fba3ddffb0e17403b9725e482582573
    use ParseCertificateODQuMzIuNDQuOTU6MjUwMDB8KG9kaykvKi0=
    """
    data = strings.extract_ascii_strings(data)
    for d in data:
        match = re.search(r'use ParseCertificate(?P<enc_c2>\S+)', d.string)
        if not match:
            continue
        try:
            raw = match.groupdict()
            encoded_c2 = raw.get("enc_c2")
            dec_c2 = base64.b64decode(encoded_c2).decode("utf-8")
            return dec_c2

        except Exception as e:
            logging.error(f"Error during extraction: {e}")
            return None

def parse_c2(raw_data: str) -> CommandAndControl:
    """Parse the stored C2: which is stored in this format `<raw_c2_ip>:<raw_c2_port>|<other data> `"""
    raw_c2 = raw_data.split("|")[0]
    raw_c2 = raw_c2.split(":")
    c2 = CommandAndControl(ip=raw_c2[0], port=int(raw_c2[1]))
    return c2

class Kaiji(Extractor):
    author = "Sekoia.io"
    last_modified = "26-02-2025"
    category = [CategoryEnum.bot, CategoryEnum.ddos]
    family = 'Kaiji'
    yara_rule = """
    rule Kaiji_variant_chaos
    {
        meta:
            author = "Sekoia IO"
            malware = "ChaosBotnet"
            description = "Catch ChaosBotnet on common instruction and pattern"
            hash = "90c7c13411a2cdcfaeb61905f768c828"
            hash = "a8d011f4307646fe859353631421fa13"
            hash = "ff226c9145fc5b1c78edd5e302154cdd"
            hash = "4d587de47760a1ba3da618ec63a4254b"
        strings:
            $v = "main.chaos_" ascii
            $go = "GOOS=linux" ascii
            $f1 = "_cve_run" ascii
            $f2 = "_ipspoof" ascii
            $f3 = "_ssh_attack" ascii
            $f4 = "reverseshell" ascii
            $f5 = "Getmypwd" ascii
        condition:
            uint32be(0) == 0x7f454c46 and #v > 50 and $go and 4 of ($f*) and filesize > 5000KB and filesize < 6000KB
    }

    rule Kaiji_variant_ares
    {
        meta:
            author = "Sekoia IO"
            malware = "AresBotnet"
            description = "Catch AresBotnet on common instruction and pattern"
            hash = "e13e9c0520aaa1a51d2c9737145c35cc"
            hash = "4395091ac7b78f768b10087e4f4635a2"
            hash = "2fba3ddffb0e17403b9725e482582573"
            hash = "b7eb8e66f765a5c0a8d0ddf3ff763c3e"
        strings:
            $v = "main.Ares_" ascii
            $go = "GOOS=linux" ascii
            $f1 = "Tcp_Keep_Hex" ascii
            $f2 = "_ipspoof" ascii
            $f3 = "_L3_Udp_Hex" ascii
            $f4 = "_Ws_Keep_Hex" ascii
            $f5 = "main.attack" ascii
        condition:
            uint32be(0) == 0x7f454c46 and #v > 50 and $go and 4 of ($f*) and filesize > 5000KB and filesize < 6000KB
    }
    """

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[ExtractorModel]:
        data = stream.read()

        if not data:
            logging.error(f"no data")
            return None

        for hit in matches:
            if any(filter(lambda hit: hit.rule.startswith("Kaiji"), matches)):
                ret = ExtractorModel(family=self.family, version="Linux", category=self.category)
                try:
                    raw_c2 = extract_b64_and_decode(data)
                    c2 = parse_c2(raw_c2)

                    if matches[0].rule == "Kaiji_variant_chaos":
                        ret.family = "ChaosBotnet"

                    if matches[0].rule == "Kaiji_variant_ares":
                        ret.family = "AresBotnet"

                    if c2:
                        connection_kwargs = {
                            "server_port": c2.port,
                            "usage": ConnUsageEnum.c2,
                        }
                        if check_ip(c2.ip):
                            connection_kwargs["server_ip"] = c2.ip
                        else:
                            connection_kwargs["server_domain"] = c2.ip
                        ret.tcp.append(ret.Connection(**connection_kwargs))

                    return ret

                except Exception as e:
                    logging.error(f"error during extraction: {e}")
                    return None

            else:
                return None
