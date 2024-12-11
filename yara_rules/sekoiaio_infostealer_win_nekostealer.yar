rule sekoiaio_infostealer_win_nekostealer {
    meta:
        id = "8b7d2708-9d33-4855-8e02-f6afedb7dda8"
        version = "1.0"
        description = "Detect the NekoStealer infostealer based on specific strings"
        source = "Sekoia.io"
        creation_date = "2023-01-24"
        classification = "TLP:CLEAR"
        
    strings:
        $nek = "NekoStealer.Stealing" ascii
        
        $str01 = "\\Local Storage\\leveldb" wide
        $str02 = "======================= Discord Tokens =======================" wide
        $str03 = "======================== IP Information ========================" wide
        $str04 = "https://ipapi.co/" wide
        
    condition:
        uint16(0) == 0x5A4D and (#nek > 10 or all of ($str*))
}
        