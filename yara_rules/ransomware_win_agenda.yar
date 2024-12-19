rule ransomware_win_agenda {
    meta:
        version = "1.0"
        description = "Finds Agenda ransomware (aka Qilin) samples based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2022-12-15"
        id = "b0ea8e69-8f29-452f-95f7-67ee0e545b66"
        classification = "TLP:CLEAR"
        
    strings:
        $str00 = "\"note\": \"-- Qilin" ascii
        $str01 = "README-RECOVER-.txt" ascii
        $str02 = "\"file_black_list\": [" ascii
        $str03 = "\"file_pattern_black_list\": [" ascii
        $str04 = "Encrypted files have new extension." ascii
        $str05 = "We have downloaded compromising and sensitive data from you system/network" ascii
        $str06 = "Employees personal dataCVsDLSSN." ascii
        $str07 = "ueegj65kwr3v3sjhli73gjtmfnh2uqlte3vyg2kkyqq7cja2yx2ptaad.onion" ascii
        $str08 = "cmdvssadmin.exe delete shadows /all /quiet" ascii
        $str09 = "[WARNING] Removing shadows failed." ascii
        $str10 = "[INFO] Shadow copies removed" ascii
        $str11 = "[WARNING] net sahre enum failed with:" ascii
        
    condition:
        uint16(0)==0x5A4D and 2 of them
}
        