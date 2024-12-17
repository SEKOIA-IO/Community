rule sekoiaio_apt_susp_lazarus_dangerous_password {
    meta:
        id = "726c8b92-7fbe-40f8-917a-cabd206028da"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-09-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ".jpeg" wide
        $ = "mshta"
        
    condition:
        uint32be(0) == 0x4c000000 and all of them and filesize < 5KB
}
        