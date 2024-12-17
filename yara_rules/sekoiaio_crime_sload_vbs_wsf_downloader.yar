rule sekoiaio_crime_sload_vbs_wsf_downloader {
    meta:
        id = "55d87205-5f8f-479a-a616-bf3fce571f03"
        version = "1.0"
        description = "Detects sLoad Downloader"
        author = "Sekoia.io"
        creation_date = "2022-08-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { 53 65 74 20 6c 69 6e 6b 20 3d 20 [5-10] 2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 }
        $ = { 2e 72 75 6e 20 22 63 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [5-10] 2e 6c 6e 6b 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c }
        $ = { 3d 22 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 22 }
        $ = { 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 22 20 26 20 }
        
    condition:
        2 of them and filesize < 1KB
}
        