rule sekoiaio_stealer_win_demotryspy {
    meta:
        id = "70af0e40-b177-49a3-bff4-723f3f4aa375"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2024-02-09"
        classification = "TLP:CLEAR"
        reference = "https://paper.seebug.org/3115/"
        
    strings:
        $demotry1 = "DemoTry.exe"
        $demotry2 = "DemoTry\\Release\\DemoTry.pdb"
        
        $wide1 = "\\loc.tmp" wide
        $wide2 = "\\log.tmp" wide
        $wide3 = "\\Google\\Chrome\\User Data" wide
        $wide4 = "\\Default\\Login data" wide
        $wide5 = "\\Local State" wide
        
    condition:
        uint16be(0) == 0x4d5a and (1 of ($demotry*) or all of ($wide*))
}
        