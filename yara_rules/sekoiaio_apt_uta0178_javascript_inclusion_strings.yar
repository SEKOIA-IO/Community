rule sekoiaio_apt_uta0178_javascript_inclusion_strings {
    meta:
        id = "af816c35-1f00-47ea-86ee-c034607c625e"
        version = "1.0"
        description = "Detects UTA0178 malicious inclusion strings"
        author = "Sekoia.io"
        creation_date = "2024-01-12"
        classification = "TLP:CLEAR"
        
    strings:
        $s0 = ".value"
        $s1 = "btoa("
        $s2 = "https://"
        $s3 = "new XMLHttpRequest();"
        $s4 = ".send(null);"
        
    condition:
        @s0 < @s1 and 
        @s1 < @s2 and 
        @s2 < @s3 and 
        @s3 < @s4 and
        @s4-@s0 < 350
}
        