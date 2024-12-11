rule sekoiaio_apt_susp_apt28_uac0063_malicious_doc {
    meta:
        id = "2b9d597a-a6cd-49df-8938-7103342a1d06"
        version = "1.0"
        description = "Detects some suspected APT28 document"
        source = "Sekoia.io"
        creation_date = "2024-07-25"
        classification = "TLP:CLEAR"
        hash = "93322be0785556e627d2b09832c18e39c115e6a6fbff64b1e590e1ddcf8f6a43"
        
    strings:
        $ = "Sub pop() : : End Sub" ascii fullword
        $ = "%localappdata%\\Temp" ascii fullword
        $ = "rthedbv" ascii fullword
        
    condition:
        2 of them and filesize < 1MB
}
        