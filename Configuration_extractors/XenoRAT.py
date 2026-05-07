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
            "ServerIp": None,
            "ServerPort": None,
            "delay": None,
            "mutex_string": None,
            "Install_path": None,
            "startup_name": None,
        }
        for type in module.GetTypes():
            if type.Name == "Program":
                for method in type.Methods:
                    if method.Name == ".cctor":
                        instructions = list(method.Body.Instructions)
                        for inst_1, inst_2 in zip(instructions, instructions[1:]):
                            if (inst_2.OpCode == OpCodes.Stsfld) and (
                                inst_1.OpCode == OpCodes.Ldstr
                                or inst_1.OpCode.Name.startswith("ldc.i4")
                            ):
                                field_name = str(inst_2.Operand.Name)
                                if field_name in config:
                                    config[field_name] = str(inst_1.Operand)
    except Exception as e:
        logging.error(f"erreur in extract setting {e}")
    else:
        return config


class XenoRAT(Extractor):

    family = "XenoRAT"
    author = "Sekoia.io"
    last_modified = "17-09-2025"
    category = [CategoryEnum.rat, CategoryEnum.infostealer]
    yara_rule = """
    rule XenoRAT_rat_win
    {
        meta:
            version = "1.0"
            author = "Sekoia IO"
            malware = "XenoRAT"
            creation_date = "2024-02-09"
            modification_date = "2025-10-07"
            description = "Xeno RAT is an open-source RAT, used by kimsuky in january 2024"
            hash = "c886878129bd048c3d7d3dced82858f6"
            hash = "e0b465d3bd1ec5e95aee016951d55640"
            hash = "21843600eea5443841bf6dfe692630a3"
        strings:
            $s = "moom825"
            $x = "xeno_rat_client"
        condition:
            uint16be(0) == 0x4d5a and $s and #x > 20 and filesize > 43KB and filesize < 50KB
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
            if any(filter(lambda hit: hit.rule.startswith("XenoRAT_rat_win"), matches)):
                try:
                    other = {}
                    settings = extract_setting(data)
                    hosts, port = (
                        settings.get("ServerIp"),
                        settings.get("ServerPort"),
                    )
                    if not (hosts and port):
                        logging.error("no C2 extraction")
                        return

                    ret = ExtractorModel(
                        family=self.family, version="Windows", category=self.category
                    )
                    if settings.get("mutex_string") is not None:
                        ret.mutex = [settings.get("mutex_string")]
                    conn_kwargs = {"server_port": port, "usage": ConnUsageEnum.c2}
                    if check_ip(hosts):
                        conn_kwargs["server_ip"] = hosts
                    else:
                        conn_kwargs["server_domain"] = hosts
                    ret.tcp.append(ret.Connection(**conn_kwargs))

                    ret.other = {
                        k: settings[k]
                        for k in ("Install_path", "startup_name", "delay")
                        if k in settings
                    }

                    return ret

                except Exception as e:
                    logging.error(f"error on run - {e}")
            else:
                return
