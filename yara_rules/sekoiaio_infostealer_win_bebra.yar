rule sekoiaio_infostealer_win_bebra {
    meta:
        id = "e84d04a7-1232-47e5-b797-ac8e56066796"
        version = "1.0"
        description = "Find samples of Bebra Stealer based on specific strings"
        source = "Sekoia.io"
        creation_date = "2023-02-06"
        classification = "TLP:CLEAR"
        hash = "7841746c54c53dbcafdf3f357c7a84b90fe3b089e07f30dea15ef6f7f15b0f00"
        
    strings:
        $str01 = "https://studio.youtube.com/youtubei/v1/att/esr?alt=json&key=" ascii
        $str02 = "https://www.youtube.com/getAccountSwitcher" ascii
        $str03 = "\"challenge\":\"" ascii
        $str04 = "\"botguardResponse\":\"" ascii
        $str05 = "\"continueUrl\":\"https://studio.youtube.com/reauth\"," ascii
        $str06 = "\"flow\":\"REAUTH_FLOW_YT_STUDIO_COLD_LOAD\"," ascii
        $str07 = "\"xguardClientStatus\":0" ascii
        $str08 = "SAPISIDHASH" ascii
        $str09 = "system32\\cmd.exe /C choice /C Y /N /D Y /T 0 &Del" ascii
        $str10 = "/new.php" ascii
        $str11 = "github.com/mattn/go-sqlite3" ascii
        
    condition:
        uint16(0)==0x5A4D and 9 of them
}
        