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
from lief.ELF import ARCH
from lief.ELF import Header
from capstone import *
from capstone.x86 import *
from capstone.arm import *
from capstone.arm64 import *

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


class Disassembler:
    def __init__(self, binary: lief.ELF.Binary):
        self.binary = binary
        self.arch = binary.header.machine_type
        self.entry = binary.entrypoint
        self.md = self._init_capstone()

    def _init_capstone(self):
        if self.arch == lief.ELF.ARCH.I386:
            return Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.arch == lief.ELF.ARCH.AARCH64:
            return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif self.arch == lief.ELF.ARCH.ARM:
            # 32-bit ARM
            # CS_MODE_ARM: standard 32-bit instructions (4 bytes)
            # CS_MODE_THUMB: 16-bit compressed instructions (Thumb mode)
            mode = CS_MODE_THUMB if self.entry & 1 else CS_MODE_ARM
            return Cs(CS_ARCH_ARM, mode)
        elif self.arch == lief.ELF.ARCH.X86_64:
            return Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise ValueError(f"unsupport arch: {self.arch}")

    def _get_step(self) -> int:
        if self.arch in [ARCH.ARM, ARCH.MIPS, ARCH.AARCH64]:
            # Fixed-size instructions: 4 bytes
            # If disassembly fails, we can safely skip 4 bytes
            return 4
        elif self.arch in [ARCH.X86_64, ARCH.I386]:
            # Variable-length instructions (1 to 15 bytes)
            # If disassembly fails, advance byte by byte to avoid missing any valid instruction
            return 1
        else:
            # generic fallback
            return 2

    def disasm(self, code: bytes, base_addr: int) -> List[CsInsn]:
        offset = 0
        step = self._get_step()
        end = len(code)
        results = []
        self.md.detail = True

        while offset < end:
            try:
                instr = list(self.md.disasm(code[offset:], base_addr + offset, count=1))

                if not instr:
                    offset += step
                    continue

                instr = instr[0]
                results.append(instr)
                offset += instr.size

            except Exception as e:
                offset += step
        return results


class ConfigExtractor:
    def __init__(self, binary: lief.ELF.Binary):
        self.binary = binary
        self.arch = binary.header.machine_type

    @classmethod
    def from_binary(cls, binary):
        """
        Main interface to find the address/offset passed to a function call.
        Dispatches to architecture-specific implementation.
        """
        arch = binary.header.machine_type
        if arch in [ARCH.I386, ARCH.X86_64]:
            return ConfigExtractorX86(binary)
        elif arch in [ARCH.ARM, ARCH.AARCH64]:
            return ConfigExtractorARM(binary)
        else:
            raise ValueError(f"Unsupported architecture: {arch}")

    def find_symbol(self, func: str) -> Optional[int]:
        """
        Searches the ELF binary for a symbol with the specified name and returns its
        address if found.
        """
        try:
            for sym in self.binary.symbols:
                if sym.name == func:
                    addr = sym.value
                    return addr
        except Exception as e:
            logging.error(f"error on symbol {func} search : {e}")
            return

    def extract_data(self, addr: int, offset: int) -> Optional[bytes]:
        try:
            raw = self.binary.get_content_from_virtual_address(addr, offset)
            data = bytes(raw).split(b"\x00")[0]
        except Exception as e:
            print(f"error dans extract {e}")
            return
        else:
            return data

    def run(self) -> Optional[CommandAndControl]:
        try:
            if self.arch in [ARCH.X86_64, ARCH.ARM, ARCH.I386]:

                # init step: search functions address to use as reference point
                ServerConnectCli_addr = self.find_symbol("ServerConnectCli")
                c2_resolv_func_addr = self.find_symbol("send_dns_request")
                inet_addr = self.find_symbol("inet_addr")
                htons_addr = self.find_symbol("htons")

                if not (ServerConnectCli_addr and htons_addr):
                    print("Missing some reference functions address")
                    logging.error("Missing some reference functions address")
                    return

                # disas binary and build instruction list
                text = self.binary.get_section(".text")
                disasm = Disassembler(self.binary)
                instructions = disasm.disasm(bytes(text.content), text.virtual_address)

                # search c2 and port var address on asm instr by looking close to ref functions address
                # case 1: IP address is pass as arg on inet_addr on ServerConnectCli function
                c2_addr = self.find_addr(instructions, inet_addr, ServerConnectCli_addr)
                raw_c2 = self.extract_data(c2_addr, 16)
                if not raw_c2:
                    # case 2: fallback - IP adress is acceed by dns resolving  function
                    c2_addr = self.find_addr(instructions, c2_resolv_func_addr)
                    raw_c2 = self.extract_data(c2_addr, 16)
                    if not raw_c2:
                        print("Missing c2 IP/Dom value")
                        logging.error("Missing c2 IP/Dom value")
                        return

                port_addr = self.find_addr(
                    instructions, htons_addr, ServerConnectCli_addr
                )
                raw_port = self.extract_data(port_addr, 4)

                if not raw_port:
                    print("Missing c2 Port value")
                    logging.error("Missing c2 Port value")
                    return

                ip = bytes(raw_c2).decode("utf-8", errors="ignore")
                port = bytes(raw_port).split(b"\x00")[0]

                if self.binary.header.identity_data == lief.ELF.Header.ELF_DATA.MSB:
                    indian = "big"
                else:
                    indian = "little"

                c2 = CommandAndControl(ip=ip, port=int.from_bytes(port, indian))
                return c2

        except Exception as e:
            print(f"Extraction error : {e}")
            logging.error(f"Extraction error : {e}")
            return


class ConfigExtractorX86(ConfigExtractor):
    def find_addr(
        self, instructions: List[CsInsn], func_addr: int, start_addr: int = None
    ) -> Optional[int]:
        return self.find_addr_x86(instructions, func_addr, start_addr)

    def find_addr_x86(
        self, instructions: List[CsInsn], func_addr: int, start_addr: int = None
    ) -> Optional[int]:
        """
        Scans a list of disassembled instructions to locate a CALL to a specific function
        (identified by its immediate operand) and extracts the argument passed to that call.

        The function performs a backward analysis limited to the 5 instructions
        preceding the CALL. It attempts to resolve the argument in two cases:

            1. The argument is an immediate value directly present in the instruction
               before the CALL.
            2. The argument is stored in a register, and a preceding MOV instruction
               assigns that register either an immediate value or a memory displacement.

        Parameters
        ----------
        instructions : List[CsInsn]
            A list of Capstone instruction objects to analyze.
        func_addr : int
            The target function address we want to identify CALL instructions for.
        start_addr : int, optional
            If provided, only instructions located after this address are considered.
        """

        try:
            for idx, insn in enumerate(instructions):
                if start_addr is not None and insn.address < start_addr:
                    continue

                if insn.id == X86_INS_CALL:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM and op.imm == func_addr:
                        prev_idx_start = max(0, idx - 5)
                        prev_insts = instructions[prev_idx_start:idx]

                        for prev in reversed(prev_insts):
                            if len(prev.operands) == 2:
                                dst, src = prev.operands[0], prev.operands[1]
                                if src.type == X86_OP_IMM:
                                    return src.imm

                                if src.type == X86_OP_REG:
                                    reg = src.reg

                                    for mov_prev in reversed(prev_insts):
                                        if mov_prev.id == X86_INS_MOV:
                                            dst2, src2 = (
                                                mov_prev.operands[0],
                                                mov_prev.operands[1],
                                            )

                                            if (
                                                dst2.type == X86_OP_REG
                                                and dst2.reg == reg
                                            ):

                                                if src2.type == X86_OP_IMM:
                                                    return src2.imm

                                                if (
                                                    src2.type == X86_OP_MEM
                                                    and src2.mem.base == 0
                                                    and src2.mem.index == 0
                                                ):
                                                    return src2.mem.disp

                            elif prev.id == X86_INS_PUSH:
                                op = prev.operands[0]
                                if op.type == X86_OP_IMM:
                                    return op.imm

                                if op.type == X86_OP_REG:
                                    reg = op.reg
                                    for mov_prev in reversed(prev_insts):
                                        if mov_prev.id == X86_INS_MOV:
                                            dst2, src2 = (
                                                mov_prev.operands[0],
                                                mov_prev.operands[1],
                                            )

                                            if (
                                                dst2.type == X86_OP_REG
                                                and dst2.reg == reg
                                            ):

                                                if src2.type == X86_OP_IMM:
                                                    return src2.imm

                                                if (
                                                    src2.type == X86_OP_MEM
                                                    and src2.mem.base == 0
                                                    and src2.mem.index == 0
                                                ):
                                                    return src2.mem.disp

                            else:
                                continue

        except Exception as e:
            print(f"Error in X86 search C2 config : {e}")
            logging.error(f"Error in X86 search C2 config : {e}")

        return None


class ConfigExtractorARM(ConfigExtractor):
    def find_addr(
        self, instructions: List[CsInsn], func_addr: int, start_addr: int = None
    ) -> Optional[int]:
        return self.find_addr_arm(instructions, func_addr, start_addr)

    def find_addr_arm(
        self, instructions: List[CsInsn], func_addr: int, start_addr: int = None
    ):
        """
        ARM version of find_addr_x86
        Easy way :
        - look 5 instructions before BL/BLX to func_addr
        - extract LDR
        - if 1 LDR : PC-relative -> load literal
        - if 2 LDR : pattern base + offset : (ldr base, ldr [base,#offset])
        """

        try:
            for idx, insn in enumerate(instructions):

                if start_addr is not None and insn.address < start_addr:
                    continue

                if insn.id in (ARM_INS_BL, ARM_INS_BLX):
                    op = insn.operands[0]
                    if op.type != ARM_OP_IMM or op.imm != func_addr:
                        continue

                    prev = instructions[max(0, idx - 5) : idx]
                    # Extract LDR
                    ldrs = []
                    for ins in prev:
                        if ins.id == ARM_INS_LDR and len(ins.operands) >= 2:
                            ldrs.append(ins)

                    if not ldrs:
                        logging.error("No LDR found")
                        return None

                    # CASE 1 : LDR (PC-relative literal)
                    if len(ldrs) == 1:
                        ins = ldrs[0]
                        src = ins.operands[1]
                        if src.type == ARM_OP_MEM and src.mem.base == ARM_REG_PC:
                            literal_addr = ins.address + 8 + src.mem.disp
                            try:
                                data = self.binary.get_content_from_virtual_address(
                                    literal_addr, 4
                                )
                                val = int.from_bytes(data, "little")
                                return val
                            except Exception as e:
                                logging.error(f"acceed data error {e}")
                                return

                        logging.error("Single LDR but not PC-relative")
                        return None

                    # CASE 2 : 2 LDR (base + offset)
                    if len(ldrs) == 2:
                        base_ins = ldrs[0]
                        off_ins = ldrs[1]

                        # base = ldr rX, [pc,#imm]
                        base_src = base_ins.operands[1]
                        if (
                            base_src.type != ARM_OP_MEM
                            or base_src.mem.base != ARM_REG_PC
                        ):
                            logging.error(
                                "First LDR is not PC-relative, cannot process pattern"
                            )
                            return None

                        literal_addr = base_ins.address + 8 + base_src.mem.disp
                        data = self.binary.get_content_from_virtual_address(
                            literal_addr, 4
                        )
                        base_val = int.from_bytes(data, "little")

                        # offset = ldr rX, [rX,#offset]
                        off_src = off_ins.operands[1]
                        if (
                            off_src.type == ARM_OP_MEM
                            and off_src.mem.base != ARM_REG_PC
                        ):
                            offset = off_src.mem.disp
                            return base_val + offset

                        logging.error("Second LDR is not base+offset")
                        return None

                    logging.error("More than 2 LDRs, unsupported pattern")
                    return None

        except Exception as e:
            logging.error(f"Error in ARM search C2 config : {e}")
        return None


class Ddostf(Extractor):

    family = "ddostf"
    author = "Sekoia.io"
    last_modified = "04-12-2025"
    category = [CategoryEnum.ddos]
    yara_rule = """
    rule ddostf_bot_lin
    {
        meta:
            version = "1.0"
            author = "Sekoia IO"
            malware = "ddostf"
            creation_date = "2024-02-09"
            modification_date = "2025-04-12"
            description = "catch Ddostf DDoS bot based on "
            hash = "b00d41d30b0a7b289607e19367893688664d907a9d04b48feb6d88bc449ed423" // X86
            hash = "db9fceb84052afb3dc5d3ba109d1e20506a195867cc6bd319fcc47d166345129" // X86
            hash = "d2f2271938f895d5383a6ca9e2170da7545314eb234da1f72eb2bd58f027dfbe" // X86
    		hash = "b4bd3605548d0768de3c60dc9ff47ce326395a6ed80e936a4f173e32f75e4144" // ARM
            hash = "6abfea326919bc9e8191e8f87a8242107be49c00a6bf6348e84d1f2ccdbc5a61" // ARM
    		hash = "a3cb71e5f8e6417e5c0dcec0547dbfe5db5551f6e98bbd32910ff6e6b05e7be6" // MIPS - Unsupported
        strings:
            $dos = "_Flood" ascii
            $s = "ddos.tf" ascii fullword
            $att1 = "GETFT_Flood" ascii
            $att2 = "WZTCP_Flood" ascii
            $att3 = "WZUDP_Flood" ascii
            $att4 = "ICMP_Flood" ascii
            $att5 = "POST_Flood" ascii
            $att6 = "GET_Flood" ascii
        condition:
            uint32be(0) == 0x7f454c46 and #dos > 10 and 4 of ($att*) and $s and filesize > 300KB and filesize < 2MB
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
            if any(filter(lambda hit: hit.rule.startswith("ddostf_bot_lin"), matches)):
                ret = ExtractorModel(
                    family=self.family, version="Linux", category=self.category
                )
                try:
                    binary = lief.parse(raw=data)
                    config_extract = ConfigExtractor.from_binary(binary)
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
                        logging.error(f"no C2 extraction")
                        return

                    return ret

                except Exception as e:
                    logging.error(f"error on run - {e}")
            else:
                return
