rule sekoiaio_hacktool_socat_strings {
    meta:
        id = "7c7e4085-39b2-445e-a9ff-52f21936e714"
        version = "1.0"
        description = "Detects socat"
        source = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[options] <bi-address> <bi-address>"
        $ = "version %s on %s"
        $ = "socat_signal():"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 5MB and all of them
}
        