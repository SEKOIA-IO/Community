rule sekoiaio_apt_cloudmensis_downloader_strings {
    meta:
        id = "450cfa42-7b56-4d93-afe2-9cf5c1049217"
        version = "1.0"
        description = "Detects CloudMensis downloader"
        author = "Sekoia.io"
        creation_date = "2022-07-26"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
        $ = "python -c 'import os; print(os.confstr(65538))'"
        $ = "getCmdResult:"
        $ = "[pCloud DownloadFile:]"
        
    condition:
        uint32be(0) == 0xcafebabe and
        filesize < 1MB and
        all of them
}
        