import logging
import textwrap
import tempfile
from io import BytesIO
from typing import List, Optional
from pathlib import Path
from collections import defaultdict
from collections import namedtuple
from ipaddress import IPv4Address, AddressValueError

from maco import yara
from maco.extractor import Extractor
from maco.model import ExtractorModel
from maco.model import CategoryEnum
from maco.model import ConnUsageEnum

import lief
import capa.main
import capa.rules
import capa.loader
import capa.engine
import capa.features.common
import capa.features.address
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn
from capstone.x86_const import X86_INS_CALL, X86_OP_IMM, X86_INS_MOV, X86_OP_MEM
from malduck import rc4

CommandAndControl = namedtuple("CommandAndControl", ["address", "port", "rc4_key"])


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


class TShVariantDecompiler:

    rc4_capa_rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
rule:
  meta:
    name: contain loop
    authors:
      - moritz.raabe@mandiant.com
    lib: true
    scopes:
      static: function
      dynamic: unsupported  # requires characteristic features
    examples:
      - 08AC667C65D36D6542917655571E61C8:0x406EAA
  features:
    - or:
      - characteristic: loop
      - characteristic: tight loop
      - characteristic: recursive call
"""
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
rule:
  meta:
    name: encrypt data using RC4 PRGA
    namespace: data-manipulation/encryption/rc4
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: unsupported
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Cryptography::Encrypt Data::RC4 [C0027.009]
      - Cryptography::Generate Pseudo-random Sequence::RC4 PRGA [C0021.004]
    examples:
      - 34404A3FB9804977C6AB86CB991FB130:0x403DB0
      - 34404A3FB9804977C6AB86CB991FB130:0x403E50
      - 9324D1A8AE37A36AE560C37448C9705A:0x4049F0
      - 73CE04892E5F39EC82B00C02FC04C70F:0x4064C6
  features:
    - and:
      # TODO: maybe add characteristic for nzxor reg size
      - count(characteristic(nzxor)): 1
      - or:
        - match: calculate modulo 256 via x86 assembly
        # compiler may do this via zero-extended mov from 8-bit register
        - count(mnemonic(movzx)): 4 or more
      # should not call (many) functions
      - count(characteristic(calls from)): (0, 4)
      # should not be too simple or too complex (50 is picked by intuition)
      - count(basic blocks): (4, 50)
      - match: contain loop
      - optional:
        - or:
          - number: 0xFF
          - number: 0x100
    """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
rule:
  meta:
    name: calculate modulo 256 via x86 assembly
    authors:
      - moritz.raabe@mandiant.com
    lib: true
    scopes:
      static: instruction
      dynamic: unsupported  # requires mnemonic features
    mbc:
      - Data::Modulo [C0058]
    examples:
      - 9324D1A8AE37A36AE560C37448C9705A:0x4049A9
  features:
    #  and ecx, 800000FFh
    #  and ecx, 0FFh
    - and:
      - or:
        - arch: i386
        - arch: amd64
      - mnemonic: and
      - or:
        - number: 0x800000FF
        - number: 0xFF
        """
            )
        ),
    ]

    def __init__(self, path):
        self.path: str = path
        self.elf: Optional[lief.ELF] = None
        self.text: Optional[bytes] = b""
        self.instructions: List[CsInsn] = []
        self.rc4_function_address: int = 0
        self.rc4_key: bytes = b""
        self.blobs: List[bytes] = []
        self.rules = capa.rules.RuleSet(self.rc4_capa_rules)
        self.command_and_control: Optional[CommandAndControl] = None

    def decompile(self):
        """build the list of instruction using Capstone engine,
        correlated with Lief to manipulate the ELF structure"""

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        self.elf = lief.ELF.parse(self.path)
        self.text = self.elf.get_section(".text")

        if not self.text:
            return

        for insn in md.disasm(self.text.content, self.elf.imagebase + self.text.offset):
            self.instructions.append(insn)

    def search_rc4_function(self):
        """This function search the RC4 encryption function address using CAPA library"""

        extractor = capa.loader.get_extractor(
            Path(self.path),
            "auto",
            "auto",
            capa.main.BACKEND_VIV,
            [],
            should_save_workspace=False,
            disable_progress=True,
        )

        capabilities = capa.capabilities.common.find_capabilities(
            self.rules, extractor, disable_progress=True
        )
        meta = capa.loader.collect_metadata(
            [], Path(self.path), "auto", "auto", [], extractor, capabilities
        )
        meta.analysis.layout = capa.loader.compute_layout(
            self.rules, extractor, capabilities.matches
        )

        for name, value in capabilities.matches.items():
            if name == "encrypt data using RC4 PRGA":
                for match in value:
                    self.rc4_function_address = match[0]

    def search_rc4_key(self):
        """Search the RC4 key, the key is stack string, the strategy of the function
        is to search for rc4 function xref, and search for stack string construction in
        the previous instructions of the decryption call"""

        potential_rc4_keys = defaultdict(bytes)

        for offset, insn in enumerate(self.instructions):
            if insn.id == X86_INS_CALL:
                if (
                    insn.operands[0].type == X86_OP_IMM
                    and insn.operands[0].imm == self.rc4_function_address
                ):
                    # this is the equivalent of searching for x-refs to the RC4 function
                    for index, prev in enumerate(self.instructions[offset::-1]):
                        if prev.id == X86_INS_MOV:
                            if len(prev.operands) != 2:
                                continue
                            op1, op2 = prev.operands
                            if op1.type == X86_OP_MEM and op2.type == X86_OP_IMM:
                                if op2.imm >= 0 and op2.imm <= 255:
                                    # ensure its is a valide key
                                    potential_rc4_keys[
                                        op1.mem.base
                                    ] += op2.imm.to_bytes()
                        if index > 50:
                            # this is purely arbitrary value to reach previous instruction to build the RC4 key
                            break
                    if any(
                        map(
                            lambda x: x.startswith(b"\x00"), potential_rc4_keys.values()
                        )
                    ):
                        # we already found a key, no need to re-analyze another RC4 call
                        break

        for candidate in potential_rc4_keys.values():
            if candidate.startswith(b"\x00"):
                self.rc4_key = candidate[::-1].rstrip(b"\x00")
                logging.debug(f"found the RC4 key: {self.rc4_key}")
                break

    def extract_encrypted_blobs(self):
        """
        Extract the encrypted blobs to a list
        the blob are the first argument of the RC4 function, their
        addresses are push on the stack using a mov instruction with
        a direct address mov [ebp + offset], 0x<addr>
        In the memory structure, the size of the blob is stored two bytes
        prior to the encrypted blob (eg: the size_addr = mov_dst.imm - 2)
        """

        data = self.elf.get_section(".data")
        for d in filter(lambda x: len(x) > 5, data.content.tobytes().split(b"\x00")):
            self.blobs.append(d)

    def extract_c2(self):
        """Search if the C2 is in the decrypted blob, if yes, set the find_c2 to True"""

        for blob in self.blobs:
            cleartext = rc4(self.rc4_key, blob)
            data = cleartext.split(b";")
            if len(data) > 0:
                try:
                    data = data[0].decode()
                    data = data.split(":")
                    if len(data) > 1:
                        self.command_and_control = CommandAndControl(
                            address=data[0], port=data[1], rc4_key=self.rc4_key
                        )
                        break
                except Exception:
                    pass


class TShVariant(Extractor):

    author: str = "Sekoia.io"
    last_modified = "09-09-2025"
    category = [CategoryEnum.rat]
    family = "TShVariant"
    yara_rule = r"""rule TShVariant  {
    meta:
        malware = "TShVariant"
        description = "Detects TSH via the PEL challenge hardcoded key"
        source = "Sekoia.io"
    strings:
        $ = { 58 90 AE 86 F1 B9 1C F6 29 83 95 71 1D DE 58 0D }
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 10MB and
        all of them
}"""

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[ExtractorModel]:
        data = stream.read()

        if not data:
            logging.error(f"no data")
            return None

        if any(filter(lambda hit: hit.rule.startswith("TShVariant"), matches)):
            ret = ExtractorModel(family=self.family, category=self.category)

            with tempfile.NamedTemporaryFile() as fd:
                fd.write(data)

                try:
                    decompiler = TShVariantDecompiler(fd.name)
                    decompiler.decompile()
                    decompiler.search_rc4_function()
                    decompiler.search_rc4_key()
                    decompiler.extract_encrypted_blobs()
                    decompiler.extract_c2()
                except Exception as err:
                    logging.error(
                        f"failed to work with TShVariant decompiler to extract c2, error: {err}"
                    )
                else:
                    if decompiler.command_and_control:
                        connection_kwargs = {
                            "server_port": decompiler.command_and_control.port,
                            "usage": ConnUsageEnum.c2,
                        }

                        if check_ip(decompiler.command_and_control.address):
                            connection_kwargs["server_ip"] = (
                                decompiler.command_and_control.address
                            )
                        else:
                            connection_kwargs["server_domain"] = (
                                decompiler.command_and_control.address
                            )

                        ret.tcp.append(ret.Connection(**connection_kwargs))
                        return ret
