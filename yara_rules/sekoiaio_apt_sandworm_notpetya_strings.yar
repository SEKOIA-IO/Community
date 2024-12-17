rule sekoiaio_apt_sandworm_notpetya_strings {
    meta:
        id = "c6021638-1b59-4d20-a29d-95cabf256a28"
        version = "1.0"
        description = "Detects NotPetya worm"
        author = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "wevtutil cl Security &" wide
        $ = "wevtutil cl System &" wide
        $ = "u%s \\%s -accepteula -s" wide
        $ = "\\\\%ws\\admin$\\%ws" wide
        $ = "\\\\%s\\admin$" wide
        $ = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        3 of them
}
        