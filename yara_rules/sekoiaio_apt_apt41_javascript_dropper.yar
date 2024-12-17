rule sekoiaio_apt_apt41_javascript_dropper {
    meta:
        id = "fde70806-af50-4706-9daf-d39ad0564fc7"
        version = "1.0"
        description = "Detects Earth Lusca JS dropper"
        author = "Sekoia.io"
        creation_date = "2024-02-26"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "eval(function(p, a, c, k, e, r) {"
        $s2 = "|4d53"
        $s3 = "ActiveXObject"
        $x1 = " -F:* %1%"
        $x2 = "&I /r c:\\"
        $x3 = "ActiveXObject"
        
    condition:
        filesize < 2MB and
        (all of ($s*) or all of ($x*))
}
        