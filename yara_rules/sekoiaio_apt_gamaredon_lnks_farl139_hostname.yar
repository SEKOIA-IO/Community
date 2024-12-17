rule sekoiaio_apt_gamaredon_lnks_farl139_hostname {
    meta:
        id = "f8bb2e6b-e544-46b0-b61b-048fe84e1100"
        version = "1.0"
        description = "Detects some hostname used in Gamaredon LNKs"
        author = "Sekoia.io"
        creation_date = "2023-01-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "desktop-farl139"
        
    condition:
        uint32be(0) == 0x4c000000
        and all of them 
        and filesize < 10KB
}
        