rule sekoiaio_apt_susp_apt28_uac0063_malicious_doc_settings_xml {
    meta:
        id = "fd104985-6441-4fb6-8cc1-30afa4a7797b"
        version = "1.0"
        description = "Detects some suspected APT28 document settings.xml"
        source = "Sekoia.io"
        creation_date = "2024-07-25"
        classification = "TLP:CLEAR"
        hash = "0272acc6ed17c72320e4e7b0f5d449841d0ccab4ea89f48fd69d0a292cc5d39a"
        
    strings:
        $ = "http://schemas.openxmlformats.org/" ascii fullword
        $ = "Call svc.GetFolder(" ascii fullword
        $ = "CreateTextFile(appdir" ascii fullword
        $ = "Sub Document_Open() : On Error Resume Next" ascii fullword
        
    condition:
        2 of them and filesize < 1MB
}
        