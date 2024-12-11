rule sekoiaio_unknown_quad7_wildcard_login {
    meta:
        id = "01510244-0795-4299-aa66-056a2b4682e7"
        version = "1.0"
        description = "Detects the (x|r|a)login bind shells"
        source = "Sekoia.io"
        creation_date = "2024-07-18"
        classification = "TLP:CLEAR"
        hash = "4d9067e7cf517158337123a30a9bd0e3"
        hash = "43ea387b8294cc4d0baaef6d26ff7c72"
        hash = "777d6f907da38365924a0c2a12e973c5"
        hash = "8542a3cbe232fe78baa0882736c61926"
        hash = "1b08725acc371f6b7d05bb72d0c2d759"
        
    strings:
        $string1 = { 2f 62 69 6e 2f 73 68 00 2f 74 6d 70 2f 6c 6f 67 69 6e }
        $string2 = { 2f 62 69 6e 2f 73 68 00 2d 63 00 65 78 69 74 20 30 }
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 180KB and
        @string2 - @string1 < 3400
}
        