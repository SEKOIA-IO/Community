rule infostealer_win_monster_stub {
    meta:
        id = "10d27d49-79ae-4edc-8c30-35506bdf2c42"
        version = "1.0"
        description = "Finds Monster Stealer stub (Python payload) based on specific strings."
        author = "Sekoia.io"
        creation_date = "2024-08-07"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "https://t.me/monster_free_cloud" ascii
        $str02 = "MonsterUpdateService" ascii
        $str03 = "Monster.exe" ascii
        $str04 = "schtasks /create /f /sc daily /ri 30 /tn" ascii
        $str05 = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\" ascii
        $str06 = "banned_uuids" ascii
        $str07 = "banned_computer_names" ascii
        $str08 = "banned_process" ascii
        $str09 = "register_X_browsers" ascii
        $str10 = "register_payload" ascii
        $str11 = "tiktok_sessions.txt" ascii
        $str12 = "spotify_sessions.txt" ascii
        $str13 = "network_info.txt" ascii
        $str14 = "lolz.guru" ascii
        $str15 = "echo ####System Info####" ascii
        $str16 = "echo ####Firewallinfo####" ascii
        $str17 = "/injection/main/injection.js" ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of them
}
        