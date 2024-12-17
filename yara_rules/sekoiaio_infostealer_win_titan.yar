rule sekoiaio_infostealer_win_titan {
    meta:
        id = "0adbe616-0d91-4b05-b7a8-812cd79f9252"
        version = "1.0"
        description = "Finds samples of the Titan Stealer"
        author = "Sekoia.io"
        creation_date = "2023-01-12"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "/sendlog" ascii
        $str1 = "/stealer/grabfiles.go" ascii
        $str2 = "/stealer/installedsoft.go" ascii
        $str3 = "/stealer/screenshot.go" ascii
        $str4 = "/stealer/sendlog.go" ascii
        $str5 = "/stealer/userinformation.go" ascii
        $str6 = "C:/Program Files (x86)/Steam/config/" ascii
        $str7 = "/com.liberty.jaxx/IndexedDB/file__0.indexeddb.leveldb/" ascii
        $str8 = "MAC Adresses:" ascii
        $str9 = "/Coowon/Coowon/" ascii
        $str10 = "_/C_/Users/admin/Desktop/stealer_v7/stealer" ascii
        
    condition:
        uint16(0)==0x5A4D and 5 of them
}
        