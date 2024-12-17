rule sekoiaio_infostealer_win_meduzastealer {
    meta:
        id = "1276f485-aa5d-491b-89d8-77f98dc496e1"
        version = "1.0"
        description = "Finds MeduzaStealer samples based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-06-20"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "emoji" ascii
        $str02 = "%d-%m-%Y, %H:%M:%S" ascii
        $str03 = "[UTC" ascii
        $str04 = "user_name" ascii
        $str05 = "computer_name" ascii
        $str06 = "timezone" ascii
        $str07 = "current_path()" ascii
        $str08 = "[json.exception." ascii
        $str09 = "GDI32.dll" ascii
        $str10 = "GdipGetImageEncoders" ascii
        $str11 = "GetGeoInfoA" ascii
        
    condition:
        uint16(0) == 0x5a4d and 8 of them 
        and filesize > 500KB
}
        