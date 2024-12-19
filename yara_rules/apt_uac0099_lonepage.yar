rule apt_uac0099_lonepage {
    meta:
        id = "007f62f5-da5c-4df7-8b5c-5ed815ce6993"
        version = "1.0"
        description = "Detects LonePage vbs malware"
        author = "Sekoia.io"
        creation_date = "2024-01-08"
        classification = "TLP:CLEAR"
        
    strings:
        $s0 = "dim r, c" ascii fullword
        $s1 = "= createobject(\"WScript.Shell\")" ascii fullword
        $s2 = "r.Run c, 0, false" ascii fullword
        
        $t1 = "GetHostAddresses" ascii fullword nocase
        $t2 = "upgrade.txt" ascii fullword nocase
        $t3 = "net.webclient" ascii fullword nocase
        $t4 = "downloaddata" ascii fullword nocase
        $t5 = "[System.Environment]::NewLine" ascii fullword nocase
        $t6 = ".uploaddata('" ascii nocase
        
    condition:
        true and filesize < 10KB
        and 
        (
            ($s1 at 0x10 and $s0 at 0 and $s2 and 2 of ($t*)) 
            or 
            (all of ($t*) and any of ($s*))
        )
}
        