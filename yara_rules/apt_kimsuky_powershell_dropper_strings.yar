rule apt_kimsuky_powershell_dropper_strings {
    meta:
        id = "8b346e05-215b-46c0-82bf-fce3a65440f3"
        version = "1.0"
        description = "Detects a PowerShell dropper used by Kimsuky"
        author = "Sekoia.io"
        creation_date = "2024-06-11"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "try { " ascii wide
        $s2 = "); } catch(e){} } if ("
        $s3 = "WScript.Sleep("
        $s4 = " } catch(e) { }"
        
    condition:
        filesize > 500KB and
        $s1 at 0 and $s2 in (filesize-1000..filesize)
                 and $s3 in (filesize-1000..filesize)
                 and $s4 in (filesize-1000..filesize)
}
        