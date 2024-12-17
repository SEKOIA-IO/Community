rule sekoiaio_infostealer_win_raccoon_str_takemypainback {
    meta:
        version = "1.0"
        description = "Detect Raccoon based on specific strings"
        author = "Sekoia.io"
        creation_date = "2022-10-03"
        id = "2148636e-47c7-4bf2-8d1e-df68faf65111"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "\\ffcookies.txt" wide
        $str1 = "TakeMyPainBack" wide
        $str2 = "wallet.dat" wide
        $str3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $str4 = "Network\\Cookies" wide
        
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
        