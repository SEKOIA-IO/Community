rule sekoiaio_apt_apt31_pakdoor {
    meta:
        id = "463b8d0d-30f4-45ed-8f19-4b32436fbbf0"
        description = "Detects APT31 ORB implant - 2019/2021"
        version = "1.0"
        creation_date = "2021-10-11"
        classification = "TLP:CLEAR"
        author = "Sekoia.io"
        version = "1.0"
        hash = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
        
    strings:
        // Common strings between samples
        $s1 = "mv -f %s %s ;chmod 777 %s"
        $s2 = "GET /plain HTTP/1.1"
        $s3 = "exc_cmd time out"
        $s4 = "exc_cmd pipe err"
        $s5 = { 2e 2f [1-10] 20 20 64 65 6c }
        
    condition:
        int32be(0) == 0x7f454c46 and 
        filesize < 800KB and 
        filesize > 400KB and 
        4 of ($s*)
}
        