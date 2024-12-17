rule sekoiaio_tool_win_snap2html {
    meta:
        id = "9865daac-f23b-417e-813e-cbed03f45161"
        version = "1.0"
        description = "Finds Snap2HTML samples based on specific strings. Legitimate tool used by ransomware affiliates to perform discovery"
        author = "Sekoia.io"
        creation_date = "2024-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Snap2HTML.exe" fullword wide ascii
        $str02 = "Snap2HTML.Properties" ascii
        $str03 = "set_txtRoot" ascii
        $str04 = "set_chkHidden" ascii
        $str05 = "set_chkSystem" ascii
        $str06 = "set_chkLinkFiles" ascii
        $str07 = "set_txtLinkRoot" ascii
        $str08 = "set_chkOpenOutput" ascii
        $str09 = "set_txtTitle" ascii
        $str10 = "get_CancellationPending" ascii
        $str11 = "set_RootFolder" ascii
        $str12 = "add_SettingsLoaded" ascii
        
    condition:
        uint16(0) == 0x5a4d and 7 of them
}
        