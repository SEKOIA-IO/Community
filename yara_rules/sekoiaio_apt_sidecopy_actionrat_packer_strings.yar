rule sekoiaio_apt_sidecopy_actionrat_packer_strings {
    meta:
        id = "b9370bd5-12e1-448e-a5b1-2acc72adc4a7"
        version = "1.0"
        description = "Detects SideCopy's ActionRAT (packer?)"
        author = "Sekoia.io"
        creation_date = "2023-05-11"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "(HTTP/1\\.[01]) (\\d{3})(?: (.*?))?"
        $ = "cpp-httplib/0.7"
        $ = "\\HTTP Arsanel\\"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        