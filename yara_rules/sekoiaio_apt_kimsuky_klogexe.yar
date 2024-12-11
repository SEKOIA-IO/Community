rule sekoiaio_apt_kimsuky_klogexe {
    meta:
        id = "f6e3b1a5-43b6-4dac-83c2-a365c41de38d"
        version = "1.0"
        description = "Detects KLogExe, a keylogger used by Kimsuky"
        source = "Sekoia.io"
        creation_date = "2024-09-27"
        classification = "TLP:CLEAR"
        hash = "e1d683ee1746c08c5fff1c4c2b3b02f0"
        hash = "90946c6358eacd119fe1eb36ec7a0a18"
        hash = "9760f489a390665b5e7854429b550c83"
        
    strings:
        //$ = "GetAsyncKeyState" ascii wide
        //$ = "desktops.ini" ascii wide
        $event = "Norton_BreakHelper" ascii wide
        $log = "------ %d/%d/%d : %d/%d ------" ascii wide
        
        $keylog_1 = "[RM+]"
        $keylog_2 = "[Tab+]"
        $keylog_3 = "[Home+]"
        $keylog_4 = "[End+]"
        $keylog_5 = "[clip_s]: %s "
        $keylog_6 = "%s[Too many clip_tail]"
        $keylog_7 = "%s[F%d]"
        
        $user_agent = "Chrome/31.0." wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 600KB and 
        8 of them
}
        