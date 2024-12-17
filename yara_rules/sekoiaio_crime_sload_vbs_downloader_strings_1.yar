rule sekoiaio_crime_sload_vbs_downloader_strings_1 {
    meta:
        id = "77ff0d21-9249-43b2-9a6d-87988a2dec3b"
        version = "1.0"
        description = "Detects an sLoad downloader based on strings"
        author = "Sekoia.io"
        creation_date = "2022-08-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "On Error Resume Next"
        $ = {0A [4] 3D 41 72 72 61 79}
        $ = { 2E 50 61 74 74 65 72 6E 20 3D 20 22 28 [4-10] 7C [4-10] 7C [4-10] 7C [4-10] 7C [4-10] 7C [4-10] 7C [4-10] 7C }
        
    condition:
      all of them and filesize < 20KB
}
        