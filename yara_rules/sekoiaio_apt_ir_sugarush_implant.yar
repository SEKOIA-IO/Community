rule sekoiaio_apt_ir_sugarush_implant {
    meta:
        id = "bcf057cc-272c-4cb6-bb76-928788675282"
        version = "1.0"
        description = "Detects the SUGARUSH implant"
        source = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "You are offline at " wide
        $ = "\\Logs\\ServiceLog_" wide
        $ = "Service is recall at" wide
        $ = "add_OutputDataReceived" ascii
        $ = "get_CurrentDomain" ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 100KB and
        all of them
}
        