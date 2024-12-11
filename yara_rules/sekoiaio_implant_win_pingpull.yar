rule sekoiaio_implant_win_pingpull {
    meta:
        id = "521615d4-912b-4581-b5a9-a8b158ac9496"
        version = "1.0"
        description = "Detect the PingPull malware used by GALLUM in 2022"
        source = "Sekoia.io"
        creation_date = "2022-06-13"
        classification = "TLP:CLEAR"
        reference = "https://unit42.paloaltonetworks.com/pingpull-gallium/#Protections-and-Mitigations"
        
    strings:
        $ = "PROJECT_%s_%s_%08X"
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        