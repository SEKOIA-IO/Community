rule sekoiaio_apt_gobrat_2 {
    meta:
        id = "6b7e38f5-00bc-49c8-b34d-3e878bf426d8"
        version = "1.0"
        description = "Detects GobRat related files"
        source = "Sekoia.io"
        creation_date = "2024-09-10"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "thisisweird" ascii
        $ = "ZzZzZzZzZzZz"
        
    condition:
        all of them and uint32be(0) == 0x7f454c46
}
        