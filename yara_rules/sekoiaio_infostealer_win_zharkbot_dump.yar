rule sekoiaio_infostealer_win_zharkbot_dump {
    meta:
        id = "84c4f02e-fa59-4ab9-b8e8-077cd23ce117"
        version = "1.0"
        description = "Finds ZharkBot dumps based on specific strings."
        source = "Sekoia.io"
        creation_date = "2024-07-10"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "log\\Passwords.txt" ascii
        $str02 = "---------------------------------------------------------------------" ascii
        $str03 = "Browser: %s" ascii
        $str04 = "Stealer: ZharkBOT" ascii
        $str05 = "Failed to decrypt password for URL: %s" ascii
        $str06 = "Closed database and cleaned up!" ascii
        $str07 = "CREATE TEMP TABLE sqlite_temp_master(" ascii
        $str08 = "(OpiumG4ng Win32)" wide
        
    condition:
        uint16(0)==0x5A4D and (5 of them or $str08)
}
        