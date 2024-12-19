rule infostealer_win_doenerium_str {
    meta:
        id = "1645a86f-1063-4e98-a1fa-85fc8c4e9691"
        version = "1.0"
        description = "Detect the Doenerium infostealer based on specific strings"
        author = "Sekoia.io"
        creation_date = "2022-09-29"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "doenerium" ascii
        $str02 = "<================[   User Info   ]>================>" ascii
        $str03 = "<================[WiFi connections]>================>" ascii
        $str04 = "<================[Executable Info]>================>" ascii
        $str05 = "<================[ Network Data ]>================>" ascii
        $str06 = "\\Network Data.txt" ascii
        $str07 = "\\Update.exe\" --processStart" ascii
        $str09 = "\\WiFi Connections.txt" ascii
        $str10 = "\\User Info.txt" ascii
        $str11 = "\\Executable Info.txt" ascii
        $str12 = "\\Found Wallets.txt" ascii
        $str13 = "SELECT origin_url, username_value, password_value FROM logins" ascii
        $str14 = "https://cdn.discordapp.com/embed/avatars/0.png" ascii
        $str15 = "detectClipboard" ascii
        $str16 = ".gofile.io/uploadFile" ascii
        
    condition:
        uint16(0)==0x5A4D and 6 of them
}
        