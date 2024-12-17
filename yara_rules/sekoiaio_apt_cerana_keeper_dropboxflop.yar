rule sekoiaio_apt_cerana_keeper_dropboxflop {
    meta:
        id = "e077901f-3847-45f3-82cb-d52724cd3fb5"
        version = "1.0"
        description = "Detects DropboxFlop malware"
        author = "Sekoia.io"
        creation_date = "2024-10-04"
        classification = "TLP:CLEAR"
        hash = "2b65b74e52fbf25cb400dbdfcd1a06a7"
        
    strings:
        $ = "<assemblyIdentity type=\"win32\" name=\"dropboxflop\""
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them
}
        