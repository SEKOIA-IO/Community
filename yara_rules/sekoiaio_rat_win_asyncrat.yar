rule sekoiaio_rat_win_asyncrat {
    meta:
        id = "d698e4a1-77ff-4cd7-acb3-27fb16168ceb"
        version = "1.0"
        description = "Detect AsyncRAT based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-01-25"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "get_ActivatePong" ascii
        $str02 = "get_SslClient" ascii
        $str03 = "get_TcpClient" ascii
        $str04 = "get_SendSync" ascii
        $str05 = "get_IsConnected" ascii
        $str06 = "set_UseShellExecute" ascii
        $str07 = "Pastebin" wide
        $str08 = "Select * from AntivirusProduct" wide
        $str09 = "Stub.exe" wide
        $str10 = "timeout 3 > NUL" wide
        $str11 = "/c schtasks /create /f /sc onlogon /rl highest /tn " wide
        $str12 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        
    condition:
        uint16(0) == 0x5A4D and 9 of them
}
        