rule sekoiaio_infostealer_win_nosu {
    meta:
        version = "1.0"
        description = "Finds Nosu samples based on characteristic strings"
        source = "Sekoia.io"
        creation_date = "2022-12-15"
        id = "9823af25-e30b-4514-a59c-02dd19fe368d"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "C:\\xampp\\htdocs\\nosu\\core\\release\\lilly.pdb" ascii
        $str1 = "{\"gp\":\"%s\",\"app\":\"%S\"," ascii
        $str2 = "stored in zip:\\%s" wide
        
    condition:
        uint16(0)==0x5A4D and 1 of them and filesize<1MB
}
        