rule sekoiaio_crime_sload_zip_archives {
    meta:
        id = "5335ad65-bca5-4937-8634-46cbd7aa1b0e"
        version = "1.0"
        description = "Detects ZIP archives used by sLOad"
        author = "Sekoia.io"
        creation_date = "2022-08-01"
        classification = "TLP:CLEAR"
        
    strings:
        $pic = { 00 00 00 [6] 2E ( 70 6E 67 | 67 69 66 | 6a 70 67 | 6A 70 65 67 ) }
        $pdf = { 00 00 00 [8] 2E 70 64 66 }
        $vbs = { ( 4c 65 67 67 69 6d 69 | 66 69 73 63 ) 2e ( 77 73 66 | 76 62 73 ) }
        
    condition:
        uint16be(0) == 0x504B
        and filesize < 30KB
        and all of them
}
        