rule sekoiaio_infostealer_win_whitesnake_stealer_feb23 {
    meta:
        id = "68ae7fbc-4486-4b60-af5e-f37ddc58f170"
        version = "1.0"
        description = "Finds WhiteSnake samples (stealer module)"
        author = "Sekoia.io"
        creation_date = "2023-03-01"
        classification = "TLP:CLEAR"
        
    strings:
        $fun01 = "Ibhiyptxjhiacrnxomvqjb" ascii
        $fun02 = "Irwcvmgzsduiiizaabbczm" ascii
        
        $whi = "WhiteSnake.Properties.Resources" ascii
        
        $str01 = "get_UtcNow" ascii
        $str02 = "get_IPAddress" ascii
        $str03= "get_Ticks" ascii
        $str04 = "set_commands" ascii
        $str05 = "set_Information" ascii
        $str06 = "set_filedata" ascii
        $str07 = "get_Jpeg" ascii
        $str08 = "set_Culture" ascii
        $str09 = "MakeScreenshot" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        ((all of ($fun*) or $whi) and 3 of ($str*) or
        7 of ($str*)) and
        filesize < 100KB
}
        