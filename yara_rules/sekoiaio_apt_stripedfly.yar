rule sekoiaio_apt_stripedfly {
    meta:
        id = "81968d34-3247-4965-ba44-55747370c90e"
        version = "1.0"
        description = "Detects string relative to Stripedfly malware"
        author = "Sekoia.io"
        creation_date = "2023-11-30"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "{\"id\":%d,\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}"
        $s2 = "{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"\"}"
        $s3 = "(tcp|ssl)://([A-Za-z0-9\\.\\-]+):([0-9]+)"
        
    condition:
        filesize < 3MB and 2 of them
}
        