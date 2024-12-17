rule sekoiaio_win_loader_astasialoader_strings {
    meta:
        id = "8dfabf28-4b5a-43db-87e9-5b9080541ec3"
        version = "1.0"
        description = "AstasiaLoader strings"
        author = "Sekoia.io"
        creation_date = "2023-08-16"
        classification = "TLP:CLEAR"
        hash = "44b6f7508a82ff6a4d65defc189303eeee393b5fd498de73d74d0a2c75c87401"
        
    strings:
        $s1 = "newuploaders" wide
        $s2 = "\\infected.exe" wide
        $s3 = "AstasiaLoader" wide
        $s4 = "Astasia.pdb" ascii
        $s5 = "ip-api.com/line/?fields=hosting" wide
        $s6 = "https://api.telegram.org/bot" wide
        $s7 = "currentscript.txt" wide
        $s8 = "sessionlog.txt" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 50KB and filesize < 1MB and
        5 of them
}
        