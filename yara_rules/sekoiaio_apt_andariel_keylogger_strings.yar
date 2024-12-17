rule sekoiaio_apt_andariel_keylogger_strings {
    meta:
        id = "59e94bee-9bd4-4f72-9358-858956bb4787"
        version = "1.0"
        description = "Detects one of the Andariel keylogger"
        author = "Sekoia.io"
        creation_date = "2024-06-17"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Username:%s [%d/%02d/%02d %02d:%02d]" ascii fullword
        $ = "-------[%d/%02d/%02d %02d:%02d]"
        $ = "{Insert}"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 300KB and
        2 of them
}
        