rule sekoiaio_downloader_mac_smooth_operator {
    meta:
        id = "c132b3f0-f536-4a66-bcf8-2a95c258c414"
        version = "1.0"
        description = "Detect the Smooth_Operator malware"
        author = "Sekoia.io"
        creation_date = "2023-07-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%s/.main_storage"
        $ = "%s/UpdateAgent"
        
    condition:
        uint32be(0)==0xcafebabe and all of them
}
        