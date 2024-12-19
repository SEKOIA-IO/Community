rule launcher_win_stealthmutant_bat_launcher {
    meta:
        id = "7452291f-2244-469e-bb7c-5eff1ca17aa2"
        version = "1.0"
        description = "StealthMutant/StealthVector bat launcher"
        author = "Sekoia.io"
        creation_date = "2021-08-26"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "set \"WORK_DIR=" ascii
        $s2 = "set \"DLL_NAME=" ascii
        $s3 = "set \"SERVICE_NAME=" ascii
        $s4 = "set \"DISPLAY_NAME=" ascii
        $s5 = "set \"DESCRIPTION=" ascii
        
        $start = "@echo off" ascii
        $end = "net start \"%SERVICE_NAME%\"" ascii
        
    condition:
        uint16(0)!=0x5A4D  
        and all of ($s*)
        and filesize < 2KB
        and $start at 0
        and $end in (filesize-30..filesize)
}
        