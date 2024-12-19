rule guloader_unpacker_decoded {
    meta:
        id = "ca3f4fce-b3a1-4672-a2ca-29ea347eb23d"
        version = "1.0"
        description = "GuLoader Unpacker b64 decoded"
        author = "Sekoia.io"
        creation_date = "2024-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $jumps = {71 01 9b 71 01 9b}
        $s1 = "([String]$"
        $s2 = "For($"
        $s3 = ",[Parameter(Position = 1)] [Type] $"
        
    condition:
        filesize < 500KB and @jumps < 1000 and 2 of ($s*)
}
        