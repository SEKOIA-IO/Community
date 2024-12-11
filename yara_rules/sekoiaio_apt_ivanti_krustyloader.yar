rule sekoiaio_apt_ivanti_krustyloader {
    meta:
        id = "617fdd5f-7555-49e8-b0ec-2199f017dc40"
        version = "1.0"
        description = "Detects KrustyLoader used in the Ivanti campaign"
        source = "Sekoia.io"
        creation_date = "2024-01-29"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "/proc/self/exe" ascii fullword
        $s2 = "||||||||||||||"
        $s3 = "/tmp/"
        $xor = {40 80 f5}
        $chunk_1 = {
        66 0F EF D0
        66 0F 6F C3
        66 0F 73 F8 0C
        66 0F EF C1
        66 0F EF C2
        66 0F EF C3
        } // used for crypto but not specific to Krustyloader
        
    condition:
        uint32be(0) == 0x7f454c46 and filesize < 2MB and all of them
        and #xor > 2 and #chunk_1 > 6
        and @s3 < @s2 and @s2 < @s3+300 //$s2 is less than 300 bytes after $s3
}
        