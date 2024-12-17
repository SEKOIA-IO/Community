rule sekoiaio_infostealer_win_44caliber {
    meta:
        id = "44e5bbc1-f442-47d3-8431-25182f38439d"
        version = "1.0"
        description = "Finds samples of the 44Caliber stealer"
        author = "Sekoia.io"
        reference = "https://github.com/razexgod/44CALIBER"
        creation_date = "2022-03-08"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "44 CALIBER" fullword ascii
        $str1 = "https://api.vimeworld.ru/user/name/" wide
        $str2 = "https://freegeoip.app/xml/" wide
        $str3 = "SOFTWARE\\Wow6432Node\\Valve\\Steam" wide
        $str4 = "VPN\\NordVPN\\\\accounts.txt" wide
        $str5 = "OpenVPN Connect\\profiles" wide
        $str6 = "FuckTheSystem Copyright"  wide
        $str7 = "lolz.guru"  wide
        $str8 = "xss.is" wide
        $str9 = "Test message recieved successfully! :raised_hands:" wide
        $str10 = "Specify a single character: either D or F" wide
        
    condition:
        uint16(0)==0x5A4D and
        9 of ($str*) and
        filesize > 100KB and filesize < 1MB
}
        