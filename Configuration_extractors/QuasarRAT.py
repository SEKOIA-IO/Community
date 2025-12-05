import clr

clr.AddReference("System.Memory")
from System.Reflection import Assembly, MethodInfo, BindingFlags
from System import Type
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

import string
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad

import logging
from io import BytesIO
from typing import List, Optional, Dict, Tuple
from collections import defaultdict, Counter

from maco.extractor import Extractor
from maco.model import ExtractorModel, Encryption
from maco.model import ConnUsageEnum, CategoryEnum
from maco import yara
from ipaddress import IPv4Address, AddressValueError

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

def custom_uri_extraction(uri: str) -> Tuple[str, int]:
    """Clean up a bit the URI, some decryption uncorrectly
    unpad the plaintext and there are some remaing character,
    afterward the function split the uri (ip:potr) to return
    each part separately"""

    # remove the trailing character
    while not uri.endswith(tuple(string.digits)) and len(uri) > 0:
        uri = uri[:-1]

    ip, port = uri.split(":")
    return ip, int(port)

class ExtractionError(Exception):
    """Raised when the config extraction fails or a required value is missing."""
    pass

class QuasarRAT(Extractor):
    family: str = "QuasarRAT"
    author: str = "Sekoia.io"
    last_modified: str = "27-03-2025"

    yara_rule = r"""
rule QuasarRAT {
    meta:
        author = "JPCERT/CC Incident Response Group"
    strings:
        $quasarstr1 = "Client.exe" wide
        $quasarstr2 = "({0}:{1}:{2})" wide
        $sql1 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $sql2 = "{0}d : {1}h : {2}m : {3}s" wide
        $sql3 = "SELECT * FROM FirewallProduct" wide
        $net1 = "echo DONT CLOSE THIS WINDOW!" wide
        $net2 = "freegeoip.net/xml/" wide
        $net3 = "http://api.ipify.org/" wide
        $resource = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 }
    condition: ((all of ($quasarstr*) or all of ($sql*)) and $resource) or all of ($net*)
}
"""

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[ExtractorModel]:
        data = stream.read()
        if not data:
            return

        if not any(map(lambda hit: hit.rule.startswith("QuasarRAT"), matches)):
            return
        ret = ExtractorModel(family=self.family)
        ret.category.append(CategoryEnum.rat)

        configuration = self.extract(data)
        if not configuration:
            return None
        ip, port = custom_uri_extraction(configuration.get("c2_server"))
        if ip:
            connection_kwargs = {
                "server_port": port,
                "usage": ConnUsageEnum.c2,
            }
            if check_ip(ip):
                connection_kwargs["server_ip"] = ip
            else:
                connection_kwargs["server_domain"] = ip
            ret.tcp.append(ret.Connection(**connection_kwargs))

        logging.debug(configuration)
        if configuration.get("version"):
            ret.version = configuration.get("version")
        if configuration.get("botnet"):
            ret.campaign_id = configuration.get("botnet")
        ret.mutex = [configuration.get("mutex")]
        ret.campaign_id = [configuration.get("botnet")]
        ret.encryption = [
            Encryption(
                algorithm="AES",
                mode="CBC",
                seed=configuration.get("seed"),
                key=configuration.get("AES_key"),
                usage=Encryption.UsageEnum.config,
            )
        ]
        ret.paths = [
            ExtractorModel.Path(
                path=f"%APPDATA%\\{configuration.get('install_name')}",
                usage=ExtractorModel.Path.UsageEnum.install,
            )
        ]
        ret.registry = [
            ExtractorModel.Registry(
                key=rf"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{configuration.get('startup_key')}",
                usage=ExtractorModel.Registry.UsageEnum.persistence,
            )
        ]
        return ret

    def extract(self, blob: bytes) -> Optional[dict]:
        """main function used to extract QuasarRAT configuration,
        this is based on dnlib"""

        try:
            ext = DotNetQuasarRAT(blob)
            configuration = ext.extract_configuration()
        except Exception as err:
            self.logger.error(
                f"Error occured during QuasarRAT configuration extraction, error is: {err}"
            )
        else:
            return configuration


class DotNetQuasarRAT:
    """Use another class to ensure all the dotnet stuff is erased properly"""

    def __init__(self, blob: bytes):
        self.blob = blob
        self.module = dnlib.DotNet.ModuleDefMD.Load(blob)
        self.crypto_class = None  # .NET class that contains the crypto function (AES decrypt, key derivation, etc.)
        self.configuration = {
            "version": "",
            "c2_server": "",
            "subdirectory": "",
            "install_name": "",
            "mutex": "",
            "startup_key": "",
            "botnet": "",
            "logs": "",
        }
        self.BLOCK_SIZE = 16

    def extract_configuration(self) -> Dict:
        """main function of the extractor, all the logic goes here"""

        crypto_class = self.search_crypto_class()
        seed = self.search_seed_value(crypto_class)
        logging.debug(f"The seed for PBKF2 key derivation is: {seed.hex()}")
        xref_init = self.search_init_crypt(crypto_class)
        settings = self.search_caller(xref_init[0], xref_init[1])
        logging.debug(f"Settings ref are: {settings[0]}, {settings[1]}")
        settings_class = self.get_class_by_name(settings[0])

        aes_key = self.search_aes_key(settings_class)
        logging.debug(f"AES done: {aes_key}")
        encrypted_configuration = self.extract_all_encrypted_configuration(
            settings_class
        )
        logging.debug(f"extract encrypted configuration : {encrypted_configuration}")
        encrypted_configuration.remove(aes_key)

        plaintexts = []
        for encrypted_string in encrypted_configuration:
            try:
                plaintexts.append(
                    self.decrypt(aes_key, seed, encrypted_string).decode()
                )
            except Exception as er:
                logging.debug(f"error during decryption: {er}")
                logging.error(
                    f"[-] error decrypting {encrypted_string}, error is: {er}"
                )

        self.configuration = dict(zip(self.configuration.keys(), plaintexts))
        self.configuration["AES_key"] = aes_key
        self.configuration["seed"] = seed.hex()
        return self.configuration

    def decrypt(self, key: str, salt: bytes, ciphertext: bytes):
        """QuasarRAT string decryption routine.
        Each obfuscated string is stored in base64 after decoding,
        the string have this structure:
           . - The 32 first bytes are this the HMAC of the encrypted part of the string
             - The 16 following bytes defined the Initial Vector (IV)
             - The remaining bytes are the ciphertext
        """
        ciphertext = base64.b64decode(ciphertext)
        aes_key = PBKDF2(key, salt, 16, 50000)
        cipher = AES.new(aes_key, AES.MODE_CBC, ciphertext[32 : 32 + 16])
        plaintext = cipher.decrypt(ciphertext[48:])
        return unpad(plaintext, self.BLOCK_SIZE)

    def search_crypto_class(self):
        """This function iterate over all class and methods
        of the module for the creation of the AesCryptoServiceProvider
        """

        for mtype in self.module.GetTypes():
            if not mtype.HasMethods:
                continue
            for method in mtype.Methods:
                if not method.HasBody:
                    continue
                if not method.Body.HasInstructions:
                    continue
                if len(method.Body.Instructions) < 20:
                    continue
                for ptr in method.Body.Instructions:
                    # Verify that a crypto provider is contructed
                    if (
                        ptr.OpCode == OpCodes.Newobj
                        and ptr.Operand.FullName
                        == "System.Void System.Security.Cryptography.AesCryptoServiceProvider::.ctor()"
                    ):
                        logging.debug(
                            f"Crypto class found {method.FullName} in {mtype.Name}"
                        )
                        return mtype

    def get_field_from_struct(self, struct_name: str) -> Optional[bytes]:
        """becareful the variable module must be global,
        this function returns as bytes the requested field from the given
        structure `struct_name`."""

        for typeDef in self.module.Types:
            for field in typeDef.Fields:
                if field.Name == struct_name:
                    logging.debug(f"Found struct: {field.Name}")
                    # Extract raw data
                    if field.HasFieldRVA:
                        return bytes(field.InitialValue)

    def get_constant_from_class(self, mclass, variable_name: str) -> str:
        """Get the value of a variable args: @variable_name
        defined in the given class args: @mclass"""

        for m in mclass.Methods:
            prev_instr = None  # Track previous instruction
            if m.IsStatic and m.Name == ".cctor":
                # Scan the IL instructions to find the constant assignment
                for instr in m.Body.Instructions:
                    if instr.OpCode == OpCodes.Stsfld and instr.Operand is not None:
                        field = instr.Operand
                        if field.Name == variable_name:
                            # Get the previous instruction that loads the constant
                            if prev_instr is not None:
                                if (
                                    prev_instr.OpCode == OpCodes.Ldc_I4
                                ):  # Integer constant
                                    return prev_instr.GetLdcI4Value()
                                elif (
                                    prev_instr.OpCode == OpCodes.Ldc_R4
                                ):  # Float constant
                                    return prev_instr.Operand
                                elif (
                                    prev_instr.OpCode == OpCodes.Ldstr
                                ):  # String constant
                                    return prev_instr.Operand
                    prev_instr = instr

        raise ExtractionError(f"failed to read {variable_name} constant from class {mclass.FullName}")

    def extract_all_encrypted_configuration(self, mclass) -> list:
        """extract the raw encrypted string of the
        settings class of QuasarRAT, all this strings
        are built in the constructor method `.cctor`
        """

        constants = []
        static_ctor = next(
            (m for m in mclass.Methods if m.IsStatic and m.Name == ".cctor"), None
        )

        if not static_ctor or not static_ctor.HasBody:
            logging.error(
                f"Static constructor (.cctor) not found in class '{mclass.FullName}'."
            )
            return constants

        prev_instr = None  # Track previous instruction
        for instr in static_ctor.Body.Instructions:
            if instr.OpCode == OpCodes.Stsfld and instr.Operand is not None:
                if prev_instr is not None:
                    # Extract the constant value from the previous instruction
                    if prev_instr.OpCode == OpCodes.Ldstr:  # String constant
                        constants.append(prev_instr.Operand)
            prev_instr = instr  # Update previous instruction

        return constants

    def search_seed_value(self, c_crypto) -> bytes:
        """Search the seed value that is defined as a constante in the crypto class,
        as it is an array and a static member of the crypto class, and by chance
        this is the only constant of the class we search for a method with the
        static constructor attribut. Due to .NET object/compilation this array
        is built as follow:
            1. In the .cctor of the class there is a ldtoken (Load Token) the token is defined
               in another static class within a structure
            2. call void <redacted path> RuntimeHelpers::InitialzeArray(<redacted>)
            3. stsfld unit8[] CryptoClass::seed_member (stsfld stands for Store Static Field
        """

        for i in c_crypto.Fields:
            if i.IsPublic:
                logging.debug(f"found salt variable name: {i.FullName}")
                if i.constant is None and i.initialValue is None:
                    logging.debug(
                        f"{i.FullName} is a static variable built in the cctor of {c_crypto.Name} class"
                    )

        for m in c_crypto.Methods:
            if m.IsStaticConstructor:
                # the seed is always a byte array -> System.Byte[]
                for instr in m.Body.Instructions:
                    if instr.OpCode.Name == "ldtoken":
                        init_var_name = (
                            instr.Operand.get_Name()
                        )  # <- we get the name of the static field here
                        seed = self.get_field_from_struct(
                            init_var_name
                        )  # <- simply retrieve the structure member value
                        if seed:
                            return seed

        raise ExtractionError("no seed found in the sample")

    def search_caller(
        self, class_name: str, method_name: str
    ) -> Tuple[str, str]:
        # Iterate over all types in the assembly
        for typeDef in self.module.Types:
            for method in typeDef.Methods:
                if not method.HasBody:
                    continue  # Skip methods without a body

                # Scan IL instructions for calls to A::func1
                for instr in method.Body.Instructions:
                    if instr.OpCode == OpCodes.Call and instr.Operand is not None:
                        if (
                            instr.Operand.Name == method_name
                            and instr.Operand.DeclaringType.Name == class_name
                        ):
                            return typeDef.Name, method.Name

        raise ExtractionError(f"Failed to get {method_name} from {class_name}")

    def search_init_crypt(self, crypto_class) -> Tuple[str, str]:
        """This function used the class that does the cryptographic operation
        base64 decode > AES decrypt etc. to look for the function that initialize
        the AES key, PS: the key derivation using PBKF2. To do this it search over the different
        method until it finds one that call Security.Cryptography.Rfc2898DeriveBytes object constructor
        """

        for m in crypto_class.Methods:
            if len(m.Body.Instructions) > 30:
                continue
            for instr in m.Body.Instructions:
                if (
                    instr.OpCode == OpCodes.Newobj
                    and instr.Operand.FullName.startswith(
                        "System.Void System.Security.Cryptography.Rfc2898DeriveBytes::.ctor("
                    )
                ):
                    logging.debug(
                        f"method {m.FullName} call the Cryptography.Rfc2898DeriveBytes function {instr.Operand.FullName}"
                    )
                    xref_crypto_init_class_method = (crypto_class.FullName, str(m.Name))
                    return xref_crypto_init_class_method

        raise ExtractionError("no ref to System.Void System.Security.Cryptography.Rfc2898DeriveBytes::.ctor found, cannot extract init crypto class caller ")

                
    def get_class_by_name(self, target_class: str):
        """ "Simply iterate over all the class of the module until
        it finds the class by its name"""

        for mtype in self.module.GetTypes():
            if mtype.FullName == target_class:
                return mtype

    def search_aes_key(self, mclass) -> str:
        """The initialize function of the Settings class
        before some call, the second one is the one that pass the
        AES key to the derivation function, so this function built
        a sort of dict that contains the number of time a function
        is call"""

        for m in mclass.Methods:
            ldsfld, calls = 0, defaultdict(int)
            for instr in m.Body.Instructions:
                if instr.OpCode == OpCodes.Ldsfld:
                    ldsfld += 1
                elif instr.OpCode == OpCodes.Call:
                    calls[str(instr.Operand.Name)] += 1
            if any(filter(lambda x: x > 2, calls.values())):
                # Here we search the function that initialize the AES key (PBKF2)
                # There is only one call to this function and the only arg is the
                # ref token to the AES key that is going to be derived
                callers = self.get_func_parameter(m)
                counting = [n for v in callers.values() for n in v]
                values_counting = Counter(counting)
                unique = {
                    num
                    for values in callers.values()
                    if all(values_counting[n] == 1 for n in values)
                    for num in values
                }

                AES_key_variable = unique.pop()
                logging.debug(f"The AES key is located in {AES_key_variable.FullName}")
                aes_key = self.get_constant_from_class(mclass, AES_key_variable.Name)
                logging.debug(f"The AES key value is: {aes_key}")
                return aes_key

        raise ExtractionError("no AES key found")

    def get_func_parameter(self, method) -> defaultdict:
        """This only work in this context of func that take only ONE parameter"""

        is_call = None
        callers_with_args = defaultdict(list)

        reversed_instructions = list(method.Body.Instructions)[::-1]

        # read the function instruction backward
        # because the instruction in charge of passing
        # the argument are executed first, the function
        # requires to known which function is call before
        # saving the argument

        # this technique only works because here the function
        # only have ONE parameters
        for instr in reversed_instructions:
            if instr.OpCode == OpCodes.Call:
                is_call = instr.Operand
            if instr.OpCode == OpCodes.Ldsfld and is_call:
                callers_with_args[is_call].append(instr.Operand)
                logging.debug(f"{is_call} args: {instr.Operand}")
                is_call = None
        return callers_with_args


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser("QuasarRAT extractor")
    parser.add_argument(
        "-f", "--file",
        type=argparse.FileType("rb"),
        help="Path to the QuasarRAT sample",
        required=True,
    )
    args = parser.parse_args()
    blob = args.file.read()
        
    ext = DotNetQuasarRAT(blob)
    configuration = ext.extract_configuration()
    print(configuration)
