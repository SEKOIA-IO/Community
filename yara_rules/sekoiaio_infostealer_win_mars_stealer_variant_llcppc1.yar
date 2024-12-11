rule sekoiaio_infostealer_win_mars_stealer_variant_llcppc1 {
    meta:
        id = "3e2c7440b2fc9e4b039e6fa8152ac8fe"
        version = "1.0"
        description = "Detect Mars Stealer variand llcppc1"
        source = "Sekoia.io"
        creation_date = "2022-03-10"
        classification = "TLP:CLEAR"
        
    strings:
        $a = {ff 15 ?? ?? ?? ?? 89 45 ?? 6a 14 68 ?? ?? ?? ?? ff 75 ?? e8 23 00 00 00 ff 75 ?? ff 75 ?? ff 75 ?? e8 5c 00 00 00}
        
    condition:
        uint16(0)==0x5A4D and $a
}
        