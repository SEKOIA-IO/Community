rule sekoiaio_rootkit_win_purplefox_360_tct {
    meta:
        id = "e992d574-6a44-4bea-97e2-6d5579ce8d01"
        version = "1.0"
        description = "Detects Purple Fox payloads used during end-2021 and 2022 campaigns based on characteristics shared by TrendMicro details."
        source = "Sekoia.io"
        reference = "https://www.trendmicro.com/en_us/research/22/c/purple-fox-uses-new-arrival-vector-and-improves-malware-arsenal.html"
        creation_date = "2022-03-28"
        classification = "TLP:CLEAR"
        
    strings:
        $rar = "Rar!"
        $str0 = "svchost.txt"
        $str1 = "rundll3222.exe"
        $str2 = "ojbkcg.exe"
        
    condition:
        $rar at 0 and
        all of ($str*) and
        filesize > 800KB and filesize < 2800KB
}
        