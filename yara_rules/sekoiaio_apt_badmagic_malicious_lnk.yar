rule sekoiaio_apt_badmagic_malicious_lnk {
    meta:
        id = "731bd51d-c4e4-4efb-9fa8-f981a8555ed3"
        version = "1.0"
        description = "Detect LNK used by BadMagic to execute MSI payloads."
        source = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "/i http" wide
        $ = ".msi /quiet" wide
        $ = "%WINDIR%\\System32\\msiexec.exe"
        
    condition:
        uint32be(0) == 0x4c000000 and
        filesize < 1KB and
        all of them
}
        