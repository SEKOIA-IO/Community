rule sekoiaio_ursnif_ldr4 {
    meta:
        description = "Ursnif LDR4"
        source = "Sekoia.io"
        id = "73e63481-8a89-4342-87f0-8dc7ad459396"
        version = "1.0"
        classification = "TLP:CLEAR"
        source = "Sekoia.io"
        
    strings:
        $str1 = "LOADER.dll" fullword
        $str2 = "DllRegisterServer" fullword
        $str3 = ".bss" fullword
        $x64_code1 = { 3D 2E 62 73 73 74 0A 48 83 C7 28 }
        $x64_code2 = { 8B 17 48 83 C7 04 8B CA 8b C2 23 CB 0B C3 F7 D1 23 C8 41 2B CA 44 8B D2 41 89 08 41 8B CB 49 83 C0 04 83 E1 07 FF C1 41 D3 C2 41 83 EB 04 79 }
        $x64_code3 = { 41 0F B6 01 49 FF C1 8B C8 8B D0 83 E1 03 C1 E1 03 D3 E2 44 03 C2 41 83 C2 FF 75 }
        $x64_code4 = { 45 8D 45 08 48 8D 8C 24 [4] BA 30 00 FE 7F E8 }
        $x64_code5 = { 48 8D 8C 24 [4] BA 30 00 FE 7F 41 B8 08 00 00 00 E8 }
        $x86_code1 = { 81 F9 2E 62 73 73 74 09 83 C6 28 }
        $x86_code2 = { 8B 06 8B D0 23 55 0C 8B D8 0B 5D 0C F7 D2 23 D3 2B D1 8A 4D 08 80 E1 07 83 C6 04 89 17 83 C7 04 FE C1 D3 C0 83 6D 08 04 8B C8 79 }
        $x86_code3 = { 8A 0E 0F B6 D1 8B CA 83 E1 03 C1 E1 03 D3 E2 46 03 C2 4F 75 }
        $x86_code4 = { 6A 08 8D 45 F8 68 30 00 FE 7F 50 E8 }
        
    condition:
        true and 5 of them
}
        