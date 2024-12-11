rule sekoiaio_apt_lazarus_vhd_ransomware_downloader {
    meta:
        id = "edcc9df8-650c-437a-adb8-a671e8b75e64"
        version = "1.0"
        description = "Detects VHD ransomware downloader"
        source = "Sekoia.io"
        creation_date = "2022-11-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "rundll32.exe %s #1 %S" wide
        $ = "cmd /c timeout /t 10 & Del /f /q \"%s\" & attrib -s -h \"%s\" & rundll32 \"%s\" #1" wide
        $ = "cmd /c timeout /t 10 & rundll32 \"%s\" #1" wide
        $ = "curl -A cur1-agent -L %s -s -d da"
        $ = "curl -A cur1-agent -L %s -s -d dl"
        
    condition:
        filesize < 2MB and
        3 of them
}
        