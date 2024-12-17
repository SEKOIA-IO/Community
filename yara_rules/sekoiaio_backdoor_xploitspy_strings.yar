rule sekoiaio_backdoor_xploitspy_strings {
    meta:
        id = "0aa86c2e-dba6-4ef4-a47e-f1b43e04f1f3"
        version = "1.0"
        description = "Detects XploitSPY DEX file"
        author = "Sekoia.io"
        creation_date = "2022-08-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { 04 30 78 43 42 00 }
        $ = { 04 30 78 43 4C 00 }
        $ = { 04 30 78 43 4F 00 }
        $ = { 04 30 78 46 49 00 }
        $ = { 04 30 78 47 50 00 }
        $ = { 04 30 78 49 4E 00 }
        $ = { 04 30 78 4C 4F 00 }
        $ = { 04 30 78 4D 49 00 }
        $ = { 04 30 78 4E 4F 00 }
        $ = { 04 30 78 50 4D 00 }
        $ = { 04 30 78 53 4D 00 }
        $ = { 04 30 78 57 49 00 }
        
    condition:
        uint32be(0) == 0x6465780A and
        filesize < 1MB and
        10 of them
}
        