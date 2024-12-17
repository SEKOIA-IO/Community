rule sekoiaio_apt_konni_dropper {
    meta:
        id = "0783a55e-1d1e-40ca-a661-2c5dec6d78d6"
        version = "1.0"
        description = "Detects Konni dropper used when distributed via malicious document"
        author = "Sekoia.io"
        creation_date = "2023-11-27"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "UnzipAFile"
        $ = "check.bat"
        $ = "FOF_SILENT"
        $ = "fLieObj"
        
    condition:
        
        filesize < 1MB and 3 of them
}
        