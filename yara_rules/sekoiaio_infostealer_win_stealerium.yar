rule sekoiaio_infostealer_win_stealerium {
    meta:
        version = "1.0"
        description = "Detects Stealerium based on specific strings"
        author = "Sekoia.io"
        creation_date = "2022-12-01"
        id = "165c7d3d-de7e-4d71-b94a-8ab4a0e5ddd5"
        classification = "TLP:CLEAR"
        
    strings:
        $stl = "Stealerium" ascii wide
        
        $str01 = "Processe: " wide
        $str02 = "Compname: " wide
        $str03 = "Language: " wide
        $str04 = "SandBoxie: " wide
        $str05 = "== System Info ==" wide
        $str06 = "== Hardware ==" wide
        $str07 = "== Domains ==" wide
        $str08 = "WEBCAMS COUNT: " wide
        $str09 = "[Virtualization]" wide
        $str10 = "[Open google maps](" wide
        $str11 = "Remember password: " wide
        $str12 = "Target.Browsers.Firefox" ascii
        $str13 = "Modules.Keylogger" ascii
        $str14 = "ClipperAddresses" ascii
        $str15 = "ChromiumPswPaths" ascii
        $str16 = "DetectedBankingServices" ascii
        $str17 = "DetectCryptocurrencyServices" ascii
        $str18 = "CheckRemoteDebuggerPresent" ascii
        $str19 = "GetConnectedCamerasCount" ascii
        $str20 = "costura.discord-webhook-client.dll.compressed" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and filesize>1MB and ((#stl > 5 and 2 of ($str*)) or 15 of ($str*))
}
        