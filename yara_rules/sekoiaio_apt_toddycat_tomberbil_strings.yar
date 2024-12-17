rule sekoiaio_apt_toddycat_tomberbil_strings {
    meta:
        id = "b16f4d35-ea59-4439-8ddb-2c0415b97b9b"
        version = "1.0"
        description = "Detects TomBerBil password stealer"
        author = "Sekoia.io"
        creation_date = "2024-04-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[+] Begin" ascii wide
        $ = "[+] Delete File" ascii wide
        $ = "[+] Current user" ascii wide
        $ = "[+] Impersonate user" ascii wide
        $ = "[+] Local State File" ascii wide
        $ = "[>] Profile" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        4 of them
}
        