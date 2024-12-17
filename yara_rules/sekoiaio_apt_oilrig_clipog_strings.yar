rule sekoiaio_apt_oilrig_clipog_strings {
    meta:
        id = "0ac40fd9-f67d-41fa-a774-77a3a1b7cac3"
        version = "1.0"
        description = "Detects OilRig's Clipog stealer"
        author = "Sekoia.io"
        creation_date = "2023-10-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[ClipBoard=" wide
        $ = "[NUMPAD .]" wide
        $ = "[SPACE]" wide
        $ = "GetClipboardData"
        
    condition:
        uint16be(0) == 0x4d5a 
        and filesize < 350KB 
        and all of them
}
        