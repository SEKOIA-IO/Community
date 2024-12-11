rule sekoiaio_guerrilla_lemongroup {
    meta:
        id = "df635b5a-a19a-48ab-9a3a-9723e265c71d"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2023-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $dex = { 64 65 78 0A 30 33 ?? 00 }
        $odex = { 64 65 79 0A 30 33 ?? 00 }
        
        $s2 = "data response code===" ascii
        $s3 = "httpCon:" ascii
        $s4 = "processName :" ascii
        $s5 = "startListTasks......" ascii
        $s6 = "url==" ascii
        $s7 = "java core run ZYGOTE_PROCESS" ascii
        
        $api1 = "/api.php" ascii
        $api2 = "/event.php" ascii
        $api3 = "/apiRS.php" ascii
        
    condition:
        ($dex at 0 or $odex at 0) and
        filesize > 100KB and filesize < 5MB and
        5 of ($s*) and 1 of ($api*)
}
        