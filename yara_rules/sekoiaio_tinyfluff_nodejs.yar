rule sekoiaio_tinyfluff_nodejs {
    meta:
        id = "ca8cbd90-f275-4442-8354-b8b069e2efc3"
        version = "1.0"
        description = "Detect TinyFluff backdoor by OldGremlin"
        source = "Sekoia.io"
        creation_date = "2022-04-20"
        classification = "TLP:CLEAR"
        reference = "https://blog.group-ib.com/oldgremlin_comeback"
        hash = "bd0a6a3628f268a37ac9d708d03f57feef5ed55e"
        hash = "bd0a6a3628f268a37ac9d708d03f57feef5ed55e"
        
    strings:
        $s1 = "TinyFluff.pdb" fullword ascii
        $s2 = "node.exe" fullword wide
        
    condition:
        filesize < 500KB and
        uint16be(0) == 0x4d5a and
        all of them
}
        