import re
import socket
import logging
from io import BytesIO
from typing import List, Optional
from collections import namedtuple
from ipaddress import IPv4Address, AddressValueError

from maco import yara
from maco.extractor import Extractor
from maco.model import ExtractorModel
from maco.model import CategoryEnum
from maco.model import ConnUsageEnum

import lief
from lief import ELF
from capstone import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_RET,
    X86_OP_IMM,
)

REG_MAGIC = re.compile(rb"(l|a)(32|64)")

CommandAndControl = namedtuple("CommandAndControl", ["address", "port", "magic"])


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


class SNOWLIGHTDisassembler:
    """
    Capstone emulator configured for SNOWLIGHT downloader (EFL)
    """

    def __init__(self, malware_raw_content: bytes):
        self.malware_raw_content: bytes = malware_raw_content
        self.elf: Optional[ELF] = None
        self.got_map = {}
        self.plt_map = {}
        self.ro_data: List[bytearray] = []

    def setup(self):
        self.elf = lief.parse(self.malware_raw_content)
        self.manage_gotplt()
        self.parse_rodata()

    def parse_rodata(self):
        """The C2 is stored at the end of the rodata"""

        for sec in self.elf.sections:
            if sec.fullname.startswith(b".rodata"):
                logging.debug(
                    f"found read only data section @ 0x{sec.virtual_address:x}"
                )
                ro_data = bytearray(sec.content)
                self.ro_data = list(
                    filter(lambda x: x, ro_data.split(b"\x00"))
                )  # here threat data as strings

    def extract_c2_from_rodata(self) -> Optional[bytes]:
        for data in self.ro_data:
            try:
                if check_ip(data.decode()):
                    return data
            except Exception:
                pass

        # if no c2 found this is probably a domain
        # by default it is stored after the [kworker/0:2] string
        for idx, data in enumerate(self.ro_data):
            if data == b"[kworker/0:2]":
                return self.ro_data[idx + 1]

    def extract_magic_from_ro_data(self) -> Optional[bytes]:
        """SNOWLIGHT magic is send to the C2 to ask for the next payload
        it is an identifier of the type of infected machine:
        - `l64` means Intel arch on 64 bits proc
        - `l32` means Intel arch on 32 bits proc
        - `a32` mean ARM arch on 32 bits proc
        - `a64` mean ARM arch on 64 bits proc
        """

        for match in map(REG_MAGIC.match, self.ro_data):
            if match:
                return match.string

    def get_main_raw_data(self):
        """Search the main function in the exported functions
        it raise a ValueError if it does not found the `main` function,
        if main is found it returns it content as raw bytes"""

        main_addr: int = 0
        for exp in self.elf.exported_functions:
            if "main" in exp.name:
                main_addr = exp.address

        if main_addr == 0:
            raise ValueError("main function not found")

        sec = self.elf.section_from_virtual_address(main_addr)
        base = sec.virtual_address
        offset = main_addr - base
        data = bytearray(sec.content)

        chunk = data[offset:]
        return chunk, main_addr

    def disasm_buffer(self, buf, offset) -> List[CsInsn]:
        """Disassemble a given buffer of a x86_64 architecture
        and return a list of instructions"""

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        instructions = []
        for insn in md.disasm(bytes(buf), offset):
            instructions.append(insn)
            # stop at RET
            if insn.id == X86_INS_RET:
                logging.debug("Hit RET, stopping disassembly main function.")
                break
        return instructions

    def manage_gotplt(self):
        """
        Resolve the .gotplt sections to retrives name of symbol's
        to further identify in the disassembly which imported functions
        are called (in SNOWLIGHT case's we required to resolve `gethostname`
        to extract the TCP port of the payload)
         .1 Build a map of GOT-slot => symbol.name for JUMP_SLOT relocs
         .2 Build a map of PLT-entry => symbol.name (for direct PLT calls)
        """

        # LIEF exposes your PLT‐GOT relocations via `elf.pltgot_relocations`
        for rel in self.elf.pltgot_relocations:
            # rel.address is the VA of the GOT slot that will be patched
            symname = rel.symbol.name if rel.symbol else "<no-name>"
            self.got_map[rel.address] = symname

        plt_sec = self.elf.get_section(".plt")
        if plt_sec and len(self.elf.pltgot_relocations) > 0:
            plt_va = plt_sec.virtual_address
            plt_size = plt_sec.size
            # On x86_64 the first entry (.plt0) is 16 bytes, the rest are each 16 bytes
            PLT0_SZ = 16
            nentries = len(self.elf.pltgot_relocations)
            entry_sz = (plt_size - PLT0_SZ) // nentries

            for idx, rel in enumerate(self.elf.pltgot_relocations):
                entry_addr = plt_va + PLT0_SZ + idx * entry_sz
                self.plt_map[entry_addr] = rel.symbol.name

    def run(self) -> Optional[CommandAndControl]:
        """run the emulator to extract the command and control
        1. extract the ip from the rodata section
        2. extract raw bytes of the main function
        3. resolve the gotplt sections to identify a required imported function
        4. extract first parameter of gethostbyname (e.g.: port)
        """

        port: int = 0
        c2: Optional[bytes] = b""
        magic: Optional[bytes] = b""  # the magic is the broadcasted data to the c2
        main, offset = self.get_main_raw_data()
        instructions = self.disasm_buffer(main, offset)
        c2 = self.extract_c2_from_rodata()
        magic = self.extract_magic_from_ro_data()
        if not c2 or not magic:
            return

        for idx, insn in enumerate(instructions):
            logging.debug(f"0x{insn.address:08x}:\t{insn.mnemonic}\t{insn.op_str}")

            if insn.id == X86_INS_CALL:
                op = insn.operands[0]
                if op.type == X86_OP_IMM:
                    tgt = op.imm
                    sym = self.plt_map.get(tgt)
                    if sym:
                        logging.debug(
                            f"0x{insn.address:08x}: call  0x{tgt:08x} <{sym}@plt>"
                        )
                        if sym.startswith("gethostbyname"):
                            # now retrieve the first parameter (sockaddr_in->port)
                            # get the previous instruction that old the func parameter
                            _, op1 = instructions[idx - 1].operands
                            if op1.type == X86_OP_IMM:
                                imm = op1.imm
                                port = socket.htons(imm)
                                logging.debug(f"found SNOWLIGHT tcp port: {port}")
                                return CommandAndControl(c2, port, magic)


class SNOWLIGHT(Extractor):
    author = "Sekoia.io"
    last_modified = "28-08-2025"
    category = [CategoryEnum.downloader]
    family = "SNOWLIGHT"
    yara_rule = """
import "elf"
rule SNOWLIGHT {
    meta:
       author = "Sekoia IO"
       malware = "SNOWLIGHT"
       instrusion_set = "UNC5174"
       description = "Detect SNOWLIGHT ELF downloader based on broadcasted string and file checker"
    strings:
        $s_1 = "/tmp/log_de.log"
    	$s_2 = "[kworker/0:2]"
    	$dl_arch = { (6c | 61) ( 36 34 | 33 32 ) } // string for arch l32 or l64 for intel arch and a32 or a64 for ARM
    	$elf_magic = { 7F 45 4C 46 }
    condition:
        1 of ($s_*) and $dl_arch and $elf_magic at 0 and filesize<20KB and elf.machine == elf.EM_X86_64
}
"""

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[ExtractorModel]:
        data = stream.read()

        if not data:
            logging.error(f"no data")
            return None

        if any(filter(lambda hit: hit.rule.startswith("SNOWLIGHT"), matches)):
            ret = ExtractorModel(
                family=self.family, version="Linux", category=self.category
            )

            try:
                c2: Optional[CommandAndControl] = None
                disass = SNOWLIGHTDisassembler(data)
                disass.setup()
                c2 = disass.run()
                if c2:
                    connection_kwargs = {
                        "server_port": c2.port,
                        "usage": ConnUsageEnum.c2,
                    }
                    if check_ip(c2.address.decode()):
                        connection_kwargs["server_ip"] = c2.address.decode()
                    else:
                        connection_kwargs["server_domain"] = c2.address.decode()
                    ret.tcp.append(ret.Connection(**connection_kwargs))
                    ret.other = {"magic": c2.magic.decode()}
                else:
                    return None
            except Exception as err:
                logging.error(f"failed to disass, error: {err}")
            else:
                logging.info("extraction ends successfuly")
                return ret
