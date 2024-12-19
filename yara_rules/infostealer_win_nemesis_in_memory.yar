rule infostealer_win_nemesis_in_memory {
    meta:
        id = "01d85bd5-ea93-44ff-b36a-9cd9eb54d634"
        version = "1.0"
        description = "Finds Nemesis Stealer samples based on specific strings, from samples without strings obsucation, or from memory"
        author = "Sekoia.io"
        creation_date = "2023-03-29"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "NemesisProject.Modules." ascii
        $str02 = "~[NEMESIS INIZIALIZE]~" wide
        $str03 = "Clip_BoardText.txt" wide
        $str04 = "stealer_out.zip" wide
        $str05 = "<span style=\"color:#FFFFFF\">Number of running processes:</span>" wide
        $str06 = "<span style=\"color:#FFFFFF\">Installed FireWall: </span>" wide
        $str07 = "~[Panel_Receiving_Data]~ Incorrect data when receiving data on the panel" wide
        $str08 = "ProcessInfo_Log.txt" wide
        $str09 = "Installed_Software_Log.txt" wide
        $str10 = "Detect Data ClipBoard] - [ {DateTime.Now:MM.dd.yyyy - HH:mm:ss}]" wide
        $str11 = "VPN/ProtonVPN_Log.txt" wide
        $str12 = "VPN/Nord_Log.txt" wide
        $str13 = "Steam/SteamID_Log.txt" wide
        
    condition:
    uint16(0) == 0x5A4D and 6 of them
}
        