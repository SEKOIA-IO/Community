rule sekoiaio_crimeware_njrat_strings {
    meta:
        id = "215807ae-fbcb-478d-8941-e0787b883669"
        version = "1.0"
        description = "Detects njRAT based on some strings"
        author = "Sekoia.io"
        creation_date = "2022-08-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "set cdaudio door closed" wide
        $ = "set cdaudio door open" wide
        $ = "ping 0" wide
        $ = "[endof]" wide
        $ = "TiGeR-Firewall" wide
        $ = "NetSnifferCs" wide
        $ = "IPBlocker" wide
        $ = "Sandboxie Control" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        5 of them
}
        