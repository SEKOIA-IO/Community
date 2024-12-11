rule sekoiaio_apt_qnapworm_loader_may2022 {
    meta:
        id = "c6e87a55-73ea-4df4-ab61-b5d34968d741"
        version = "1.0"
        description = "Detects the QNAPWorm loader"
        source = "Sekoia.io"
        creation_date = "2022-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {
        66 C1 C0 05
        0F B7 D8
        81 C3 85 D0 FF FF
        66 C1 C3 02
        0F B7 C3
        0F B6 9A ?? ?? ?? ??
        33 D8
        88 1C 11
        42
        0F B6 D2
        81 FA ?? 00 00 00
        }
        
    condition:
        uint16be(0) == 0x4d5a and
        all of ($s*)
}
        