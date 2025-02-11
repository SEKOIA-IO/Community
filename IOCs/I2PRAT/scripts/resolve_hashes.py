from typing import Tuple
from dumpulator import Dumpulator, modules

ADDR_CRYPT_FUNC = 0x14000BE08  # to replace according to the sample


def get_dlls(dp: Dumpulator) -> list:
    dlls: list = []
    for mem in dp.memory.map():
        if mem.info:
            if type(mem.info[0]) == modules.Module:
                print(f"Add {mem.info[0].name} to the loaded DLLs")
                dlls.append(mem.info[0])
    return dlls


def resolve_address(dll, addr: int) -> str | None:
    for export in dll.exports:
        if export.address == addr and addr:
            return export.name


def emulate_hash(dp: Dumpulator, dlls, myhash: int) -> Tuple[str, str]:
    function_name = ""
    for dll in dlls:
        dp.call(ADDR_CRYPT_FUNC, [dll.base, myhash, 0])
        addr = dp.regs.rax
        function_name = resolve_address(dll, addr)
        if function_name:
            break
    function_name = "" if function_name is None else function_name
    if function_name == "":
        print(f"! hash 0x{myhash:<8x} unknown rax: 0x{addr:x}")
    return function_name, dll.name


dump_path = "stage2_all_dlls.dmp"
dp = Dumpulator(dump_path, quiet=True)
dlls = get_dlls(dp)
