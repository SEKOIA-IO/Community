rule merlin_crossplatform {
    meta:
        id = "c9c57f5e-26c3-43be-b2cf-10f5129d3be6"
        author = "Sekoia.io"
        creation_date = "2022-01-03"
        description = "Detects Merlin agent cross platform"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = ".CRT" ascii
        $s2 = ".tls" ascii
        $s3 = "github.com/Ne0nd0g/merlin" ascii
        $s4 = "github.com/refraction-networking" ascii
        $s5 = "SendMerlinMessage" ascii
        $s6 = "ifconfigH9" ascii
        
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f)
        and all of them
        and filesize > 5MB
        and filesize < 15MB
}
        