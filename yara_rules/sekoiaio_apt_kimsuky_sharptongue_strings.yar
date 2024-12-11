rule sekoiaio_apt_kimsuky_sharptongue_strings {
    meta:
        id = "56027edb-4e6e-40ec-a1b9-36c52b0dd3ec"
        version = "1.0"
        description = "Detects SharpTongue variants."
        source = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Post0.Open" ascii wide
        $s2 = ".php?op=" ascii wide
        $s3 = "s=s&Mid(c,ix*d+jx+1,1)" ascii wide
        $s4 = "curl -o " ascii wide
        
    condition:
        $s2 in (@s1..@s1+200) or $s2 in (@s4..@s4+200) or $s3 and filesize < 500KB
}
        