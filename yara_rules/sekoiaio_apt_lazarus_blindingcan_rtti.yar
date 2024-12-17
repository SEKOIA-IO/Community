rule sekoiaio_apt_lazarus_blindingcan_rtti {
    meta:
        id = "9a16c189-ffc1-4aa6-8582-298abaecd0ef"
        version = "1.0"
        description = "Detects BLINDINGCAN with RTTI"
        author = "Sekoia.io"
        creation_date = "2022-10-04"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = ".?AVCHTTP_Protocol@@" ascii wide fullword
        $s2 = ".?AVCFileRW@@" ascii wide fullword
        
    condition:
        all of them
}
        