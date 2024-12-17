import "pe"
        
rule sekoiaio_apt_lazarus_gopuram_backdoor {
    meta:
        id = "947d4ee3-79fa-450b-8482-beafe607baae"
        version = "1.0"
        description = "Detects Gopuram Backdoor"
        author = "Sekoia.io"
        creation_date = "2023-04-04"
        classification = "TLP:CLEAR"
        hash1 = "97b95b4a5461f950e712b82783930cb2a152ec0288c00a977983ca7788342df7"
        hash2 = "beb775af5196f30e0ee021790a4978ca7a7ac2a7cf970a5a620ffeb89cc60b2c"
        
    strings:
        $x1 = "%s\\config\\TxR\\%s.TxR.0.regtrans-ms"
        $xop = {D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE}
        $opa1 = {48 89 44 24 ?? 45 33 C9 45 33 C0 33 D2 89 5C 24 ?? 48 89 74 24 ?? 48 89 5C 24 ?? 89 7C 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 4C 24 ?? 44 8D 43 ??}
        $opa2 = {48 89 B4 24 ?? ?? ?? ?? 44 8D 43 ?? 33 D2 48 89 BC 24 ?? ?? ?? ?? 4C 89 B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 45 33 C0 33 D2 8B F8 E8 ?? ?? ?? ?? 8D 4F ?? E8 ?? ?? ?? ?? 4C 8B 4C 24 ?? 44 8D 43 ?? 48 8B C8 8B D7 48 8B F0 44 8B F7 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? E8 ?? ?? ??}
        
    condition:        (uint16(0) == 0x4d5a and filesize < 2MB
        and pe.characteristics & pe.DLL and 1 of ($x*)
   )
   or all of ($opa*)
}
        