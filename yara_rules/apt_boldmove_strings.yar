rule apt_boldmove_strings {
    meta:
        id = "0458e282-f92f-4600-964a-de6b66b4a82d"
        version = "1.0"
        description = "Detects BOLDMOVE via strings"
        author = "Sekoia.io"
        creation_date = "2023-01-16"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "cwd=%s" ascii wide
        $s2 = "executable=%s" ascii wide
        $s3 = "curl/6.12.34" ascii wide
        $s4 = "www.example.com" ascii wide
        $s5 = "GET /ws HTTP/1.1" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 4MB and 4 of them
}
        