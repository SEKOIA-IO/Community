rule sekoiaio_apt_muddywater_powgoop_decode_loop {
    meta:
        id = "644ed1c4-e0e1-496e-9efc-7d9e15565f7b"
        version = "1.0"
        description = "Detects the loop used in PowGoop and its loader"
        author = "Sekoia.io"
        creation_date = "2022-01-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "System.Collections.Generic.List[System.Object]" ascii wide
        $s2 = "$d.Add($in[$i]);" ascii wide
        $s3 = "[System.Convert]::FromBase64String(" ascii wide
        
    condition:
        filesize < 1MB and
        $s2 in (@s1..@s1+400) and
        $s3 in (@s1..@s1+400)
}
        