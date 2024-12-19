rule apt_suspected_sandworm_sdelete_wiper {
    meta:
        id = "c1419b11-33e5-4280-b92a-039719cb17d3"
        version = "1.0"
        description = "Detects Sdelete wiper"
        author = "Sekoia.io"
        creation_date = "2023-10-25"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = ".exe -accepteula -r -s -q" wide
        $s2 = "sdelete [-p passes] [-r]" wide
        $s3 = "!This program cannot be run in DOS mode."
        
    condition:
        uint16be(0) == 0x4d5a and
        $s1 and $s2 and #s3 == 2 and
        filesize < 500KB
}
        