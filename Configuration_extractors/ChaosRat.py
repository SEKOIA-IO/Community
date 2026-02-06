import re
import base64
import json
import logging
from floss import strings
from io import BytesIO
from typing import Dict, List, Optional
from collections import namedtuple
from maco.extractor import Extractor
from maco.model import ExtractorModel
from maco.model import ConnUsageEnum
from maco.model import CategoryEnum
from maco import yara
from ipaddress import IPv4Address, AddressValueError

CommandAndControl = namedtuple("CommandAndControl", ["ip", "port", "token"])


def check_ip(ioc: str) -> bool:
    """
    Use the built-in library ipadress to
    validate that the provided parameter `ioc`
    is a valid IPv4 address
    """

    try:
        IPv4Address(ioc)
    except AddressValueError:
        return False
    else:
        return True


def is_base64(value: str) -> bool:
    """
    base64 pattern validation
    try to decode a str, return true
    - if decode works
    - if len of decoded > 152 decoded string contains a JWT token
    """
    try:
        if not isinstance(value, str):
            return False
        decoded = base64.b64decode(value, validate=True)
        return len(decoded) > 152  # JWT token len
    except Exception:
        return False


def parse_config(raw: str) -> CommandAndControl | None:
    """
    Function to extract config data from json

    check if the data is a valid json file and contains 3 keys
    extract and identify values
    """
    try:
        conf = json.loads(raw)
    except:
        return

    if len(conf) != 3:
        return

    token = None
    port = None
    c2 = None
    ukn = []

    for val in conf.values():
        val = str(val)
        # eyJ JWT b64 pattern -> {"alg":....}
        if val.startswith("eyJ") and "." in val and len(val) > 100:
            token = val
        elif val.isdigit() and 1 <= int(val) <= 65535:
            port = val
        else:
            ukn.append(val)

    if len(ukn) == 1:
        c2 = ukn[0]
    else:
        return
    config = (c2, port, token)
    return config


def extract(all_str: list) -> Optional[CommandAndControl]:
    b64_pattern = r"([A-Za-z0-9+/]{40,}={0,2})"
    for str in all_str:
        match = re.search(b64_pattern, str.string)
        if match:
            raw = match.group(1)
            if is_base64(raw):
                try:
                    data = base64.b64decode(raw).decode("utf-8")
                    conf = parse_config(data)
                    if conf:
                        c2 = CommandAndControl(
                            ip=conf[0], port=int(conf[1]), token=conf[2]
                        )
                        return c2
                except Exception as e:
                    continue


class ChaosRat(Extractor):

    family = "Chaos"
    author = "Sekoia.io"
    last_modified = "06-02-2026"
    category = [CategoryEnum.rat]
    yara_rule = """
    rule chaos_bot_win
    {
        meta:
            version = "1.0"
            author = "Sekoia IO"
            malware = "ChaosRAT"
            creation_date = "2026-02-03"
            modification_date = "2026-02-03"
            description = "Catch open source ChaosRat based on strings"
            hash = "88ea0ddda0efabd6b0cf4dc3feca563b8f69e0471cda0ba65b1da3fd5d49fba9"
        strings:
            $chaos = "tiagorlampert/CHAOS" ascii
            $go = "golang" ascii
            $dep1 = "github.com/kbinani/screenshot" ascii
            $dep2 = "github.com/gorilla/websocket" ascii
        condition:
            uint16be(0) == 0x4d5a and all of ($dep*) and #chaos > 10 and #go > 5 and filesize > 2MB and filesize < 10MB
    }

    rule chaos_bot_lin
    {
        meta:
            version = "1.0"
            author = "Sekoia IO"
            malware = "ChaosRAT"
            creation_date = "2026-02-03"
            modification_date = "2026-02-03"
            description = "Catch open source ChaosRat based on strings"
            hash = "50d56dff0c531b9b5c2e80af66ec8a8d95e61ca1ed02cda05b802798262366be"
        strings:
            $chaos = "tiagorlampert/CHAOS" ascii
            $go = "golang" ascii
            $dep1 = "github.com/kbinani/screenshot" ascii
            $dep2 = "github.com/gen2brain/shm" ascii
        condition:
            uint32be(0) == 0x7f454c46 and all of ($dep*) and #chaos > 10 and #go > 5 and filesize > 2MB and filesize < 10MB
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
            if hit.rule == "chaos_bot_win":
                ret = ExtractorModel(
                    family=self.family, version="Window", category=self.category
                )
            elif hit.rule == "chaos_bot_lin":
                ret = ExtractorModel(
                    family=self.family, version="Linux", category=self.category
                )
            else:
                logging.error("no yara match")
                return
            try:
                all_str = list(strings.extract_ascii_strings(data))
                c2 = extract(all_str)

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
                else:
                    logging.error("no C2 extraction")
                    return

                return ret

            except Exception as e:
                logging.error(f"error on run - {e}")
        else:
            return
