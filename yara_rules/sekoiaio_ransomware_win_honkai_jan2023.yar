rule sekoiaio_ransomware_win_honkai_jan2023 {
    meta:
        id = "6ef91cb5-e122-4f91-bc15-3813b8f91cbf"
        version = "1.0"
        description = "Rule to detect Honkai ransomware samples."
        source = "Sekoia.io"
        creation_date = "2023-02-13"
        classification = "TLP:CLEAR"
        hash1 = "989cf96da60d9ebfb6f364717b4f0cae1667fdc7f9d89f77acc254ab47d439e6"
        
    strings:
        $s1 = "DP_Main.exe" ascii wide
        $s2 = "DP_MainForm" ascii wide
        $s3 = "DP_Main" ascii wide
        $s4 = "#DECRYPT MY FILES#.html" ascii wide
        $s5 = "/api/Encrypted.php" ascii wide
        $s6 = "http://upload.paradisenewgenshinimpact.top:2095" ascii wide
        $s7 = "main@paradisenewgenshinimpact.top" ascii wide
        $s8 = ".honkai" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and 6 of them
}
        