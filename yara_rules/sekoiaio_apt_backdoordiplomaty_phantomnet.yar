rule sekoiaio_apt_backdoordiplomaty_phantomnet {
    meta:
        id = "bbcc0664-ef2b-47db-a546-b5e0aa2a1e9a"
        version = "1.0"
        description = "Detects PhantomNet based on strings"
        source = "Sekoia.io"
        creation_date = "2024-06-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "memory load plugin failed!" wide
        $ = "Event eee!!!" ascii
        $ = "LoadWin32_x64.pdb" ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 2MB and
        2 of them
}
        