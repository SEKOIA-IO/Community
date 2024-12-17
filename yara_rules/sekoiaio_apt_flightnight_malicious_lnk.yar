rule sekoiaio_apt_flightnight_malicious_lnk {
    meta:
        id = "06f33ece-ac9f-4dd3-98fb-cd69305ee995"
        version = "1.0"
        description = "Detects malicious LNK used by FlightNight"
        author = "Sekoia.io"
        creation_date = "2024-04-02"
        classification = "TLP:CLEAR"
        
    strings:
        $s0 = "/c start /B " wide
        $s1 = ".exe &" wide
        $s2 = ".pdf" wide
        $s3 = "%CD%" wide
        
    condition:
        uint32be(0) == 0x4c000000 and
        $s1 in (@s0..@s2) and
        $s1 in (@s0..@s0+100) and
        $s3
}
        