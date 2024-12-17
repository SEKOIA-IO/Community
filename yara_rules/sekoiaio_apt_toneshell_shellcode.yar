rule sekoiaio_apt_toneshell_shellcode {
    meta:
        id = "5ac8d2e9-dbeb-42f9-8343-1281510d4411"
        version = "1.0"
        description = "Detects first bytes of ToneShell used to call the shellcode or the code to check the MagicNumber (0x17 0x03 0x03)"
        author = "Sekoia.io"
        creation_date = "2024-10-02"
        classification = "TLP:CLEAR"
        
    strings:
        $code = {55 8b ec 83 ec 0c e8 85 00 00 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 10}
        $MagicNumberParser = {
        B8 01 00 00 00
        6B C8 00
        8B 55 ??
        0F BE 04 0A
        83 F8 17
        75 ??
        B9 01 00 00 00
        C1 E1 00
        8B 55 ??
        0F BE 04 0A
        83 F8 03
        75 ??
        B9 01 00 00 00
        D1 E1
        8B 55 ??
        0F BE 04 0A
        83 F8 03
        }
        
    condition:
        any of them and filesize < 1MB
}
        