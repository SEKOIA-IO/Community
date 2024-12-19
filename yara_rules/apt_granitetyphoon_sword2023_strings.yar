rule apt_granitetyphoon_sword2023_strings {
    meta:
        id = "417b355f-9eb8-40ae-bc3b-f7f23b5ca63e"
        version = "1.0"
        description = "Detects Sword2023 malware based on strings"
        author = "Sekoia.io"
        creation_date = "2023-05-25"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "TERM=linux"
        $ = ";echo"
        $ = "sh:time out"
        $ = "sh:read stdout error"
        $ = "/proc/sys/kernel/random/uuid"
        
    condition:
        (uint32be(0) == 0x7f454c46) and
        filesize < 100KB and
        all of them
}
        