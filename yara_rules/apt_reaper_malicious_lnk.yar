rule apt_reaper_malicious_lnk {
    meta:
        id = "8f055d1b-5727-4d77-9671-cdbb1ea69d5f"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-09-12"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "*rshell.exe" wide
        $ = "/od') do call" wide
        
    condition:
        uint32be(0) == 0x4c000000 and all of them
}
        