rule sekoiaio_apt_gamaredon_subtle_paws {
    meta:
        id = "1950f886-97d2-4aa1-8f13-2947eba706e4"
        version = "1.0"
        description = "SUBTLE-PAWS powershell backdoor used by Gamaredon"
        author = "Sekoia.io"
        creation_date = "2024-02-09"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "$splitter" ascii wide
        $s2 = "[System.Convert]::FromBase64String" ascii wide
        $s3 = "$_;$var2 =\"var1\";$var3" ascii wide
        $s4 = "foreach-object{$_|powershell -noprofile -}" ascii wide
        
    condition:
        $s1 and $s2 and ($s3 or $s4) and filesize < 100KB
}
        