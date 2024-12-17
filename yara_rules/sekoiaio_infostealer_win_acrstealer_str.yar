rule sekoiaio_infostealer_win_acrstealer_str {
    meta:
        id = "63b4d6ff-0cab-44ec-9d53-bb2612371a48"
        version = "1.0"
        description = "Finds ACR Stealer standalone samples based on specific strings."
        author = "Sekoia.io"
        creation_date = "2024-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "ref.txt" ascii
        $str02 = "Wininet.dll" ascii
        $str03 = "Content-Type: application/octet-stream; boundary=----" ascii
        $str04 = "POST" ascii
        $str05 = "os_c" ascii fullword
        $str06 = "en_k" ascii fullword
        $str07 = "MyApp/1.0" ascii
        $str08 = "/Up/b" ascii
        $str09 = "Hello, World!" ascii
        $str10 = "/ujs/" ascii
        $str11 = "/Up/" ascii fullword
        $str12 = "ostr" ascii fullword
        $str13 = "brCH" ascii fullword
        $str14 = "brGk" ascii fullword
        $str15 = "https://steamcommunity.com/profiles/" ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of them
}
        