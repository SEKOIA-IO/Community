rule sekoiaio_apt_mustangpanda_xoreddll {
    meta:
        id = "73d13624-01df-41ab-b449-86db43dc6c55"
        version = "1.0"
        description = "Detects xored DLL from MustangPanda embedding a document"
        author = "Sekoia.io"
        creation_date = "2022-07-19"
        classification = "TLP:CLEAR"
        
    strings:
        $clear = "This program cannot be run in DOS mode"
        $stub = "This program cannot be run in DOS mode" xor
        $res1 = "5w>w9wR'31Z" xor
        $res2 = "r0y0~0KlBD" xor
        $res3 = "d&o&h&öé7Æ" xor
        $res4 = "9{2{5{+0" xor
        
    condition:
        $stub and any of ($res*) and not $clear and filesize < 3MB
}
        