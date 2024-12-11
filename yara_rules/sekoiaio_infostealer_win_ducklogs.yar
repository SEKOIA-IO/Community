rule sekoiaio_infostealer_win_ducklogs {
    meta:
        version = "1.0"
        description = "Detects DuckLogs based on specific strings"
        source = "Sekoia.io"
        creation_date = "2022-12-01"
        id = "165c7d3d-de7e-4d71-b94a-8ab4a0e5ddd5"
        classification = "TLP:CLEAR"
        
    strings:
        $dck = "DuckLogs" ascii wide
        
        $str01 = "CheckRemoteDebuggerPresent" ascii
        $str02 = "MozGlueNotFound" ascii
        $str03 = "get_DecryptedPassword" ascii
        $str04 = "get_Extension" ascii
        $str05 = "set_UseShellExecute" ascii
        $str06 = "FirefoxPasswords" ascii
        $str07 = "GetAllGeckoCookies" ascii
        $str08 = "GetAllBlinkDownloadsBy" ascii
        $str09 = "Grabbers" ascii
        $str10 = "Utility" ascii
        $str11 = "Persistance" ascii
        $str12 = "Clipboard" ascii
        $str13 = "WaterfoxGrabber" ascii
        $str14 = "AvastGrabber" ascii
        
    condition:
        uint16(0) == 0x5A4D and ((#dck > 4 and 2 of ($str*)) or 12 of them)
}
        