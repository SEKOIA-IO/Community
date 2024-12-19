rule loader_win_erbium {
    meta:
        version = "1.0"
        description = "Detect the Erbium loader based on specific user-agent and URI"
        author = "Sekoia.io"
        creation_date = "2022-09-30"
        id = "d1e5be62-5677-4ef4-9f10-65baf36ab619"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36" wide
        $str02 = "cloud/getHost.php?method=getstub&bid=" wide
        $str03 = "api.php?method=getstub&bid=" wide
        
        $api = "WinHttp" ascii
        
    condition:
        uint16(0)==0x5A4D and 2 of ($str*) and #api > 6
}
        