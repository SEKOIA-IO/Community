rule sekoiaio_infostealer_win_cinoshistealer {
    meta:
        id = "2e9c066b-d5e3-4a25-8954-c10af285bcd3"
        version = "1.0"
        description = "Finds Cinoshi Stealer samples based on specific strings, or PE resources"
        author = "Sekoia.io"
        creation_date = "2023-06-23"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Anaida.exe" ascii wide
        $str02 = "Anaida.pdb" ascii
        $str03 = "embedder_download_data" ascii
        $str04 = "date_password_modified" ascii
        $str05 = "card_number_encrypted" ascii
        $str06 = "set_UseZip64WhenSaving" ascii
        $str07 = "set_CommandText" ascii
        $str08 = "Nss3CouldNotBeLoaded" ascii
        $str09 = "formhistory.sqlite" wide
        $str10 = "logins.json" wide
        $str11 = "\\nss3.dll" wide
        $str12 = "\\cookies.sqlite" wide
        $str13 = "\\places.sqlite" wide
        $str14 = "\\autofill-profiles.json" wide
        
    condition:
        uint16(0) == 0x5a4d and 9 of them 
        and filesize > 400KB
}
        