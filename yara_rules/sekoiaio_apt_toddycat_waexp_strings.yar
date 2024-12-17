rule sekoiaio_apt_toddycat_waexp_strings {
    meta:
        id = "1bbb3e81-14a9-4bda-b647-b6f5255e9a16"
        version = "1.0"
        description = "Detects WAExp based on strings"
        author = "Sekoia.io"
        creation_date = "2024-04-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[>] Profile:" wide ascii
        $ = "[+] All Done" wide ascii
        $ = "[+] Files:" wide ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        all of them and filesize < 1MB
}
        