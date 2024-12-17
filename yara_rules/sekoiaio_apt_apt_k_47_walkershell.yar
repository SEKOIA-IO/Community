rule sekoiaio_apt_apt_k_47_walkershell {
    meta:
        id = "201f8415-32d4-4af1-ba80-734554ced728"
        version = "1.0"
        description = "Detects WalkerShell used by APT-K-47"
        author = "Sekoia.io"
        creation_date = "2024-02-14"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "\\n kuskure" ascii wide
        $s2 = "col.log.txt" ascii wide
        $s3 = "polor" ascii wide
        $s4 = "emit" ascii wide
        $s5 = "delta" ascii wide
        $s6 = "under process" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 4MB and all of them
}
        