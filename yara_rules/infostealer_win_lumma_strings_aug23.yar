rule infostealer_win_lumma_strings_aug23 {
    meta:
        version = "1.0"
        description = "Finds Lumma samples based on the specific strings"
        author = "Sekoia.io"
        creation_date = "2023-09-14"
        id = "728f7825-a463-4b19-b2d3-3460e4c06dc9"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "lid=%s&j=%s&ver" ascii
        $str02 = "%s (%d.%d.%d)" ascii
        $str03 = "- Screen Resoluton:" ascii
        $str04 = "- Physical Installed Memory:" ascii
        $str05 = "Content-Type: attachment/x-object" ascii
        $str06 = "Content-Type: application/x-www-form-urlencoded" ascii
        $str07 = "Content-Type: multipart/form-data; boundary=%s" wide
        $str08 = "SysmonDrv" wide
        $str09 = "TeslaBrowser/5.5" wide
        
    condition:
        uint16(0)==0x5A4D and 6 of them
}
        