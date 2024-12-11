rule sekoiaio_unknown_7777_xlogin {
    meta:
        id = "ce0beffc-f957-43ef-a739-f4a1099a7a67"
        version = "1.0"
        description = "Detects the xlogin bind shell and its variants"
        source = "Sekoia.io"
        creation_date = "2024-07-18"
        classification = "TLP:CLEAR"
        hash = "4d9067e7cf517158337123a30a9bd0e3"
        hash = "43ea387b8294cc4d0baaef6d26ff7c72"
        hash = "777d6f907da38365924a0c2a12e973c5"
        hash = "8542a3cbe232fe78baa0882736c61926"
        
    strings:
        $string1 = { 2f 62 69 6e 2f 73 68 00 2f 74 6d 70 2f 6c 6f 67 69 6e }
        $string2 = { 2F 64 65 76 2F 6E 75 6C 6C [1-3] 2F 62 69 6E 2F 73 68 00 2D 63 }
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 180KB and
        (
            (@string2 - @string1 < 3400)
        )
}
        