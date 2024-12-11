rule sekoiaio_apt_unk_dex_china_freedom_trap_spyware {
    meta:
        id = "3d66b6b8-8397-441a-a337-4a282df39591"
        version = "1.0"
        description = "Detects China Freedom Trap spyware dex file"
        source = "Sekoia.io"
        creation_date = "2022-09-07"
        classification = "TLP:CLEAR"
        hash = "ceb70fce74898ea64ded6880a978441c"
        
    strings:
        $ = "INSTALL" base64
        $ = "FAILED" base64
        $ = "TEST" base64
        $ = "ONLY" base64
        $ = "INSTALL" base64
        $ = "INCONSISTENT" base64
        $ = "CERTIFICATES" base64
        $ = "Network country iso:" base64
        $ = "Network operator name:" base64
        $ = "SIM operator name:" base64
        $ = "SIM country iso:" base64
        $ = "SIM state:" base64
        $ = "PIN REQUIRED" base64
        $ = "PUK REQUIRED" base64
        
    condition:
        uint32be(0) == 0x6465780A and
        filesize < 100KB and
        4 of them
}
        