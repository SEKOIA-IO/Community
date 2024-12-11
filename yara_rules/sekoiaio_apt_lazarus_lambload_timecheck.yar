rule sekoiaio_apt_lazarus_lambload_timecheck {
    meta:
        id = "8807c752-c34e-4c3b-9194-3a9bd2575a88"
        version = "1.0"
        description = "Detects timeCheck routine in LambLoad"
        source = "Sekoia.io"
        creation_date = "2023-11-27"
        classification = "TLP:CLEAR"
        reference = "https://www.microsoft.com/en-us/security/blog/2023/11/22/diamond-sleet-supply-chain-compromise-distributes-a-modified-cyberlink-installer/"
        
    strings:
        /*
        0x41322e 0F8567030000                  jne 41359bh
        0x413234 8D8548FBFFFF                  lea eax, [ebp - 4b8h]
        0x41323a 50                            push eax
        0x41323b E8F2490700                    call 487c32h
        0x413240 83C404                        add esp, 4
        0x413243 83781802                      cmp dword ptr [eax + 18h], 2
        0x413247 0F854E030000                  jne 41359bh
        0x41324d 8B4808                        mov ecx, dword ptr [eax + 8]
        0x413250 83F90B                        cmp ecx, 0bh
        0x413253 0F8C42030000                  jl 41359bh
        0x413259 83F90C                        cmp ecx, 0ch
        0x41325c 0F8D39030000                  jge 41359bh
        0x413262 8B4004                        mov eax, dword ptr [eax + 4]
        0x413265 83F81E                        cmp eax, 1eh
        0x413268 0F8C2D030000                  jl 41359bh
        0x41326e 83F83C                        cmp eax, 3ch
        0x413271 0F8D24030000                  jge 41359bh
        0x413277 53                            push ebx
        0x413278 57                            push edi
        0x413279 6808020000                    push 208h
        0x41327e 8D8580FDFFFF                  lea eax, [ebp - 280h]
        0x413284 6A00                          push 0
        0x413286 50                            push eax
        0x413287 C78550FBFFFF04010000          mov dword ptr [ebp - 4b0h], 104h
        */
        $chunk_1 = {
        0F 85 ?? ?? ?? ??
        8D 85 ?? ?? ?? ??
        50
        E8 ?? ?? ?? ??
        83 C4 ??
        83 78 ?? ??
        0F 85 ?? ?? ?? ??
        8B 48 ??
        83 F9 ??
        0F 8C ?? ?? ?? ??
        83 F9 ??
        0F 8D ?? ?? ?? ??
        8B 40 ??
        83 F8 ??
        0F 8C ?? ?? ?? ??
        83 F8 ??
        0F 8D ?? ?? ?? ??
        53
        57
        68 ?? ?? ?? ??
        8D 85 ?? ?? ?? ??
        6A ??
        50
        C7 85 ?? ?? ?? ?? ?? ?? ?? ??
        }
        
    condition:
        uint16be(0) == 0x4d5a and any of them
}
        