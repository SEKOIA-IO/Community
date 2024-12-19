rule ta410_control_flow_obfuscation {
    meta:
        id = "2a784f9b-3624-4c5d-8a64-db7d3c33a8f7"
        version = "1.0"
        description = "Detects control flow obfuscation used by TA410 in XXXModule_dlcore0"
        author = "Sekoia.io"
        creation_date = "2022-10-11"
        classification = "TLP:CLEAR"
        hash = "6cf78943728286d0bddd99049d81065673ab7f679029cdd5f5dc69f90197136e"
        
    strings:
        $chunk_1 = {
        E8 ?? ?? ?? ??
        83 C0 10
        3D 00 00 00 80
        7D 01
        EB ff
        }
        
        $chunk_2 = {83 C0 10 3D 00 00 00 80 7d 01 eb ff e0 50 c3 75} //Complete obfuscation
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 10MB and any of them
}
        