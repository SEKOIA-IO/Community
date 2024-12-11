rule sekoiaio_rat_win_konni_rat {
    meta:
        id = "032f1c79-6f03-4588-a4af-38b1f3ca1cb8"
        version = "1.0"
        description = "Detect the KONNI RAT DLL files (x32 and x64)"
        source = "Sekoia.io"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ".cab" wide
        $ = ".zip" wide
        $ = ".rar" wide
        $ = ".ini" wide
        $ = ".dat" wide
        $ = "%s(%d)" wide
        $ = "%s %s \"%s\"" wide
        $ = "\\Temp\\" wide
        
    condition:
        uint16(0)==0x5A4D 
        and all of them 
        and filesize > 60KB 
        and filesize < 120KB
}
        