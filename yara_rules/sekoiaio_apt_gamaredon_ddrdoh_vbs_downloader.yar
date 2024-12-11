rule sekoiaio_apt_gamaredon_ddrdoh_vbs_downloader {
    meta:
        id = "c934b95d-d81d-4f58-a752-1bb31ba8593d"
        version = "1.0"
        description = "Detects the core of the VBS Gamaredon's Telegram Downloader"
        source = "Sekoia.io"
        creation_date = "2023-01-25"
        classification = "TLP:CLEAR"
        
    strings:
        $a1 = "==([0-9\\@]+)==" ascii
        $a2 = "data\"\":\"\"(.*?)" ascii
        $a3 = ", vbcr ,\"\")" ascii
        $a4 = ", vblf ,\"\")" ascii
        $a5 = ", \"&&\" ,\"\")" ascii
        $a6 = "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4" ascii
        $b1 = "==([0-9\\@]+)==" base64
        $b2 = "data\"\":\"\"(.*?)" base64
        $b3 = ", vbcr ,\"\")" base64
        $b4 = ", vblf ,\"\")" base64
        $b5 = ", \"&&\" ,\"\")" base64
        $b6 = "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4" base64
        
    condition:
        (4 of ($a*) or 4 of ($b*)) and filesize < 50KB
}
        