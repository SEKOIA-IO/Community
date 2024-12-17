rule sekoiaio_apt_shadowpad_first_called_function {
    meta:
        id = "3ce1ffd3-5c30-4b36-b7cc-c9fa873ebc25"
        version = "1.0"
        description = "Detects entrypoint of shadowpad"
        author = "Sekoia.io"
        creation_date = "2023-01-30"
        classification = "TLP:CLEAR"
        
    strings:
        $chunk_1 = {
        48 83 EC 28
        33 C9
        FF 15 ?? ?? ?? ??
        8B 80 ?? ?? ?? ??
        3B 05 ?? ?? ?? ??
        74 ??
        E8 ?? ?? ?? ??
        E8 ?? ?? ?? ??
        EB ??
        48 8B 0D ?? ?? ?? ??
        E8 ?? ?? ?? ??
        8B C8
        FF 15 ?? ?? ?? ??
        90
        B9 28 04 00 00
        FF 15 ?? ?? ?? ??
        90
        48 83 C4 28
        C3
        }
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them
}
        