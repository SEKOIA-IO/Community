rule sekoiaio_downloader_win_curl_agent {
    meta:
        id = "ddeb2d8f-1b10-4a33-b768-d19412e8551a"
        version = "1.0"
        description = "Detect the downloader used by Bluenoroff to install it CurlAgent"
        author = "Sekoia.io"
        creation_date = "2023-05-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%s\\marcoor.dll" wide
        $ = "curl -A cur1-agent -L %s -s -d dl"
        $ = "curl -A cur1-agent -L %s -s -d da"
        $ = "cmd /c timeout /t 10 & rundll32 \"%s\" #1" wide
        $ = "cmd /c timeout /t 10 & Del /f /q \"%s\" & attrib -s -h \"%s\" & rundll32 \"%s\" #1" wide
        
    condition:
        3 of them
}
        