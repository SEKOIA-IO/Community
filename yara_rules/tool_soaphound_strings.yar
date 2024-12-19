rule tool_soaphound_strings {
    meta:
        id = "adf48506-f07d-445a-83cc-0aed3b6b55eb"
        version = "1.0"
        description = "Detects SOAPHound based on strings"
        author = "Sekoia.io"
        creation_date = "2024-11-12"
        classification = "TLP:CLEAR"
        hash = "b2a953590d75213388473fb51e6b5f2f"
        
    strings:
        $ = "Output files generated in" wide
        $ = "(&(cn=*)(!(cn=a*))(!(cn=b*))" wide
        $ = "unicodePassword" wide
        $ = "net.tcp://localhost:9389/ActiveDirectoryWebServices/" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 2MB and
        all of them
}
        