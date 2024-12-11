rule sekoiaio_infostealer_win_fwit_strings {
    meta:
        id = "332e89ad-d1fe-4da6-9354-0978ef173e78"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2023-06-22"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "C:\\ProgramData\\Temp" wide
        $s2 = "{:08x}" wide
        $s3 = "CURL_SSLVERSION" ascii // curl embedded
        
    condition:
        (uint16be(0) == 0x4d5a) and
        
        all of them
}
        