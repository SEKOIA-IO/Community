rule apt_implant_xdealer_strings {
    meta:
        id = "06ef72ca-b4e3-493b-8e01-d34b98259c6d"
        version = "1.0"
        description = "Detects XDealer based on strings"
        author = "Sekoia.io"
        creation_date = "2024-03-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "unknow_PC"
        $ = "rdp-tcp#"
        $ = "Din_%s_%s_%u_"
        $ = "nslookup %s %s"
        $ = "XFByb2dyYW1EYXRhXA=="
        
    condition:
        uint16be(0) == 0x4d5a and
        3 of them and filesize < 1MB
}
        