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
import hashlib
from Crypto.Cipher import AES


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


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def decrypt_config(b64_input: str, mutex: str) -> str:

    md5 = hashlib.md5(mutex.encode("utf-8")).digest()  # 16 bytes
    key = bytearray(32)
    key[0:16] = md5[0:16]
    key[15 : 15 + 16] = md5[0:16]
    key_bytes = bytes(key)
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    try:
        ciphertext = base64.b64decode(b64_input)
    except Exception as e:
        raise ValueError("input is not valid base64") from e

    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(plaintext_padded)

    return plaintext.decode("utf-8", errors="ignore")


def extract_setting_obfuscated(data: bytes) -> Optional[Dict[str, str]]:
    try:
        modctx = ModuleDef.CreateModuleContext()
        module = dnlib.DotNet.ModuleDefMD.Load(data, modctx)
        config = {}
        counter = 1
        for type in module.GetTypes():
            for method in type.Methods:
                if method.Name == ".cctor":
                    instructions = list(method.Body.Instructions)
                    for inst_1, inst_2 in zip(instructions, instructions[1:]):
                        if (
                            inst_1.OpCode == OpCodes.Ldstr
                            and inst_2.OpCode == OpCodes.Stsfld
                        ):
                            config[f"val{counter}"] = inst_1.Operand
                            counter += 1

        valid = all(is_base64(config.get(f"val{i}")) for i in range(1, 6))

        if valid:
            mutex_key = None
            rename_map = {
                "val1": "Hosts",
                "val2": "Port",
                "val3": "KEY",
                "val4": "SPL",
                "val5": "Groub",
                "val6": "USBNM",
            }
            for old_key, new_key in rename_map.items():
                if old_key in config:
                    config[new_key] = config.pop(old_key)

            for k, v in config.items():
                if k.startswith("val"):
                    try:
                        port = int(decrypt_config(config["Port"], v))
                    except ValueError:
                        continue
                    else:
                        mutex_key = k
                        break
            if mutex_key:
                config["Mutex"] = config.pop(mutex_key)

    except Exception as e:
        logging.error(f"erreur in extract setting {e}")
    else:
        return config


def extract_setting(data: bytes) -> Optional[Dict[str, str]]:
    try:
        modctx = ModuleDef.CreateModuleContext()
        module = dnlib.DotNet.ModuleDefMD.Load(data, modctx)
        config = {
            "Hosts": None,
            "Host": None,
            "Port": None,
            "KEY": None,
            "SPL": None,
            "Groub": None,
            "USBNM": None,
            "Mutex": None,
        }
        for type in module.GetTypes():
            if type.Name == "Settings":
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


class XWorm(Extractor):

    family = "XWorm"
    author = "Sekoia.io"
    last_modified = "17-09-2025"
    category = [CategoryEnum.rat, CategoryEnum.worm]
    yara_rule = """
    rule XWorm_rat_win_v3
    {
        meta:
            version = "1.0"
            author = "Sekoia IO"
            malware = "XWorm"
            creation_date = "2023-03-03"
            modification_date = "2025-09-17"
            description = "Finds XWorm (version XClient, v3) samples based on characteristic strings"
            hash = "d79f03dc9477b771155094418098cd3e"
            hash = "ba3b86175802fc73758ccde22e32d257"
            hash = "3b6564a9815b70bc7f269ea43539ea48"
            hash = "bb4ee0fe0c417f63a076fdc296a4f4f4"
            hash = "0f2d2d370d98f21b193a5bcfc6c78b9a"
            hash = "2f1fae087c76a26dff9cbcd0109a922a"
        strings:
            $str01 = "$VB$Local_Port" ascii
            $str02 = "$VB$Local_Host" ascii
            $str03 = "get_Jpeg" ascii
            $str04 = "get_servicePack" ascii
            $str05 = "Select * from AntivirusProduct" wide
            $str06 = "PCRestart" wide
            $str07 = "shutdown.exe /f /r /t 0" wide
            $str08 = "StopReport" wide
            $str09 = "StopDDos" wide
            $str10 = "sendPlugin" wide
            $str11 = "OfflineKeylogger Not Enabled" wide
            $str12 = "-ExecutionPolicy Bypass -File \\"" wide
            $str13 = "Content-length: 5235" wide
            $crypt01 = "RijndaelManaged" ascii
            $crypt02 = "ICryptoTransform" ascii
            $crypt03 = "System.Security.Cryptography"
            $crypt04 = "SymmetricAlgorithm"
        condition:
            uint16be(0) == 0x4d5a and 8 of ($str*) and all of ($crypt*)
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
            if any(filter(lambda hit: hit.rule.startswith("XWorm_rat_win"), matches)):
                try:
                    other = {}
                    settings = extract_setting(data)
                    if not settings.get("Mutex"):
                        settings = extract_setting_obfuscated(data)

                    mutex, hosts, port = (
                        settings.get("Mutex"),
                        settings.get("Hosts"),
                        settings.get("Port"),
                    )

                    if not (mutex and hosts and port):
                        logging.error("no C2 extraction")
                        return
                    decod_c2 = decrypt_config(hosts, mutex)
                    decod_port = decrypt_config(port, mutex)

                    ret = ExtractorModel(
                        family=self.family, version="Windows", category=self.category
                    )
                    ret.mutex = [mutex]

                    conn_kwargs = {"server_port": decod_port, "usage": ConnUsageEnum.c2}
                    for c2 in decod_c2.split(","):
                        if check_ip(c2):
                            conn_kwargs["server_ip"] = c2
                        else:
                            conn_kwargs["server_domain"] = c2
                        ret.tcp.append(ret.Connection(**conn_kwargs))

                    mappings = [
                        ("KEY", "Clear Aes Key"),
                        ("SPL", "Seperator field"),
                        ("Groub", "Version"),
                        ("USBNM", "Installation name"),
                    ]
                    ret.other = {
                        new_key: decrypt_config(settings[old_key], mutex)
                        for old_key, new_key in mappings
                        if settings.get(old_key)
                    }

                    return ret

                except Exception as e:
                    logging.error(f"error on run - {e}")
            else:
                return
