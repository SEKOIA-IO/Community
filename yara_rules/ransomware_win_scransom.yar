rule ransomware_win_scransom {
    meta:
        id = "ea799295-1332-49c6-9816-035b91fc9b4f"
        version = "1.0"
        description = "Finds ScRansom samples based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-08-24"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "TIMATOMAFULL" wide
        $str02 = ".Encrypted" wide
        $str03 = ".Encrypting" wide
        $str04 = "File Name :" wide
        $str05 = "File size :" wide
        $str06 = "TIMATOMA#" wide
        $str07 = "Already Encrypted" wide
        $str08 = "HOW TO RECOVERY FILES.TXT" wide
        $str09 = "%d folder(s) searched and %d file(s) found - %.3f second(s)" wide
        $str10 = "Search cancelled -" wide
        $str11 = "note.txt" wide
        $str12 = "Cannot sort the list while a search is in progress." wide
        $str13 = "Cancelling search, please wait..." wide
        $str14 = "Error showing process list" wide
        $str15 = "[System Process]" wide
        $str16 = "taskkill /f /im" wide
        $str17 = "kill.bat" wide
        
    condition:
        uint16(0) == 0x5a4d and 15 of them
}
        