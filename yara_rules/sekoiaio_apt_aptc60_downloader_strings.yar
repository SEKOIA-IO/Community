rule sekoiaio_apt_aptc60_downloader_strings {
    meta:
        id = "02fd6d5b-7211-46cc-bcff-ab5d78e459c0"
        version = "1.0"
        description = "Detects a simple downloader abusing wlrmdr.exe and used by APT-C-60"
        author = "Sekoia.io"
        creation_date = "2024-09-05"
        classification = "TLP:CLEAR"
        hash = "b14ef85a60ac71c669cc960bdf580144"
        
    strings:
        $ = "mydllmain" fullword
        $ = "-s 3600 -f 0 -t _ -m _ -a 11 -u" wide
        $ = "WlrMakeService" wide
        $ = "Trigger1" wide
        
    condition:
        uint16be(0) == 0x4d5a and all of them
        and filesize < 500KB
}
        