rule sekoiaio_apt_apt35_iisraid_strings {
    meta:
        id = "ee42f406-0c7e-4385-9098-409611dbe0a5"
        version = "1.0"
        description = "Detects APT35s ISSRaid implant"
        source = "Sekoia.io"
        creation_date = "2023-05-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "CHttpModule::"
        $ = "X-Forward-Verify"
        $ = "X-Beserver-Verify"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 500KB and
        all of them
}
        