rule sekoiaio_apt_muddywater_powgoop_loader {
    meta:
        id = "716b45e1-9f17-4546-a003-a7c78340d623"
        version = "1.0"
        description = "Detects the loader of PowGoop malware"
        author = "Sekoia.io"
        creation_date = "2022-01-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "$d.Add($in[$i]);" ascii wide
        $s2 = "[System.Text.Encoding]::UTF8.GetString($o);" ascii wide
        $s3 = "$i+=(1+1)" ascii wide
        $t = { 24 ?? 3d [1-15] 20 24 ?? 3b ?? ?? ?? 20 24 ?? 3b }
        
    condition:
        filesize < 50KB and
        (3 of ($s*) or $t in (filesize-50..filesize))
}
        