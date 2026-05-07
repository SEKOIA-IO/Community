import sys, struct, clr

clr.AddReference("System.Memory")
from System.Reflection import Assembly, MethodInfo, BindingFlags
from System import Type
import logging
import os

MODULES_DIR_PATH = os.path.dirname(os.path.realpath(__file__))
DNLIB_PATH = os.path.join(MODULES_DIR_PATH, "dnlib.dll")
clr.AddReference(DNLIB_PATH)

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes
from dnlib.DotNet import ModuleDef, ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from dnlib.DotNet.Writer import ModuleWriterOptions
from dnlib.DotNet.Emit import OpCodes

from typing import Dict, List, Optional
from io import BytesIO
from maco.extractor import Extractor
from maco.model import CategoryEnum
from maco.model import ConnUsageEnum
from maco.model import ExtractorModel
from maco import yara
from ipaddress import IPv4Address, AddressValueError
import base64


def is_base64(s: str) -> bool:
    """
    Try to decode b64 str to check if it's a valid b64 string or not
    """
    try:
        decoded = base64.b64decode(s, validate=True)
    except Exception:
        return False
    else:
        return True


def parse_port(port_str: str) -> int:
    """
    Check if the port is base64 encoded string otherwise try to decode and then cast it to int
    """
    try:
        if not port_str.isdigit() and is_base64(port_str):
            decoded = base64.b64decode(port_str).decode("utf-8")
            port = int(decoded)
        else:
            port = int(port_str)
    except (ValueError, base64.binascii.Error):
        raise ValueError(f"Port invalide : {port_str}")
    return port


def check_ip(ip: str) -> bool:
    """
    Use the built-in library ipadress to
    validate that the provided parameter `ip`
    is a valid IPv4 address
    """
    try:
        IPv4Address(ip)
    except AddressValueError:
        return False
    else:
        return True


def extract_setting(data: bytes) -> Optional[Dict[str, str]]:
    try:
        modctx = ModuleDef.CreateModuleContext()
        module = dnlib.DotNet.ModuleDefMD.Load(data, modctx)
        config = {
            "H": None,
            "P": None,
            "RG": None,
            "EXE": None,
            "sf": None,
            "VN": None,
            "VR": None,
            "Mutex": None,
        }
        for type in module.GetTypes():
            if type.Name == "OK":
                for method in type.Methods:
                    if method.Name == ".cctor":
                        instructions = list(method.Body.Instructions)
                        for inst_1, inst_2 in zip(instructions, instructions[1:]):
                            if (
                                inst_1.OpCode == OpCodes.Ldstr
                                and inst_2.OpCode == OpCodes.Stsfld
                            ):
                                field_name = str(inst_2.Operand.Name)
                                if field_name in config:
                                    config[field_name] = str(inst_1.Operand)
    except Exception as e:
        logging.error(f"erreur in extract setting {e}")
    else:
        return config


class Njrat(Extractor):

    family = "njRAT"
    author = "Sekoia.io"
    last_modified = "02-12-2025"
    category = [CategoryEnum.rat, CategoryEnum.worm]
    yara_rule = """
    rule Njrat_rat_win
    {
        meta:
            version = "1.0"
            author = "Sekoia IO"
            malware = "njRAT"
            creation_date = "2022-08-22"
            modification_date = "2022-08-22"
            description = "Catch njRAT based on strings"
            hash = "76790ab79dc46fa3cc4a78220ed337d4"
            hash = "b99bb526dc4b60bd79f1cfd074161f09"
            hash = "5256b09761417d2b4b20b7a6714b9f6b"
        strings:
            $ = "set cdaudio door closed" wide
            $ = "set cdaudio door open" wide
            $ = "ping 0" wide
            $ = "[endof]" wide
            $ = "TiGeR-Firewall" wide
            $ = "NetSnifferCs" wide
            $ = "IPBlocker" wide
            $ = "Sandboxie Control" wide
        condition:
            uint16be(0) == 0x4d5a and filesize < 1MB and 5 of them
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
            if any(filter(lambda hit: hit.rule.startswith("Njrat_rat_win"), matches)):
                try:
                    other = {}
                    settings = extract_setting(data)
                    hosts, port = (
                        settings.get("H"),
                        settings.get("P"),
                    )
                    if not (hosts and port):
                        logging.error("no C2 extraction")
                        return

                    ret = ExtractorModel(
                        family=self.family, version="Windows", category=self.category
                    )

                    port = parse_port(port)
                    conn_kwargs = {"server_port": port, "usage": ConnUsageEnum.c2}
                    if check_ip(hosts):
                        conn_kwargs["server_ip"] = hosts
                    else:
                        conn_kwargs["server_domain"] = hosts
                    ret.tcp.append(ret.Connection(**conn_kwargs))

                    rg = settings.get("RG")
                    if rg is not None:
                        ret.mutex = [rg]

                    vr = settings.get("VR")
                    if vr is not None:
                        ret.version = vr

                    sf = settings.get("sf")
                    exe = settings.get("EXE")
                    if sf and exe is not None:
                        other["persist_key"] = f"{sf}\\{exe}"

                    y = settings.get("Y")
                    if y is not None:
                        other["seperator_field"] = y

                    vn = settings.get("VN")
                    if vn is not None:
                        other["botnet"] = (
                            base64.b64decode(vn).decode("utf-8")
                            if is_base64(vn)
                            else vn
                        )

                    ret.other = other

                    return ret

                except Exception as e:
                    logging.error(f"error on run - {e}")
            else:
                return
