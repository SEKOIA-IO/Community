import idc
import idautils

resolve_func_addr = 0x00014000BE08  # to adapt to your context
hashes = []
for ref in idautils.XrefsTo(resolve_func_addr):
    for ea in idautils.Heads(ref.frm - 10, ref.frm):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        mnemonic = print_insn_mnem(ea)
        if mnemonic == "mov":
            operand_1 = print_operand(ea, 0)
            fn_hash = idc.get_operand_value(ea, 1)
            if operand_1 == "edx":
                print(f"0x{ea:<10x} | {mnemonic} {operand_1} 0x{fn_hash:x}")
                hashes.append(fn_hash)
for h in hashes:
    print(f"0x{h:x}", end=", ")
