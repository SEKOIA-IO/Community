rule sekoiaio_infostealer_win_blackguard_mar23 {
    meta:
        id = "65804d31-2a0c-4b22-a8d9-8cbe1497f155"
        version = "1.0"
        description = "Finds BlackGuard samples based on specific strings (March 2023, version 5)"
        source = "Sekoia.io"
        creation_date = "2023-03-27"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "==================  5.0 ==============" wide
        $str02 = "/concerts/disk.php" wide
        $str03 = "/concerts/memory.php" wide
        $str04 = "/loader_v2.txt" wide
        $str05 = "io.solarwallet.app\\Local Storage\\leveldb" wide
        $str06 = "costura.dotnetzip.dll.compressed" ascii wide
        $str07 = "set_Laskakakaska" ascii
        $str08 = "get_Yliana" ascii
        $str09 = "set_Illeona" ascii
        $str10 = "set_Gyttettfd" ascii
        
    condition:
        uint16(0) == 0x5A4D and 4 of them
}
        