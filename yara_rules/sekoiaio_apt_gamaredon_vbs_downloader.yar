rule sekoiaio_apt_gamaredon_vbs_downloader {
    meta:
        id = "13b63570-2f18-4b35-8087-9ab15c58a0d1"
        version = "1.0"
        description = "Detects small VBS loader"
        author = "Sekoia.io"
        creation_date = "2023-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "on error resume next" nocase ascii wide
        $s2 = "String('http" nocase ascii wide
        $s3 = "send()" nocase ascii wide
        $s4 = ")|Invoke-Expression" nocase ascii wide
        $s5 = "'); Invoke-Expression $" nocase ascii wide
        $s6 = "');Invoke-Expression $" nocase ascii wide
        
    condition:
        $s1 and 
        ($s2 or $s3) and 
        ($s4 or $s5 or $s6) and 
        filesize < 1KB
}
        