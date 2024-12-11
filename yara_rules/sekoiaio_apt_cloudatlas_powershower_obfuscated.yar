rule sekoiaio_apt_cloudatlas_powershower_obfuscated {
    meta:
        id = "f76ab9d8-7753-4a17-aedd-fc9c3b8cd322"
        version = "1.0"
        description = "Detects obfuscated version of PowerShower"
        source = "Sekoia.io"
        creation_date = "2022-11-29"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}" ascii wide
        $s2 = "{000}{001}{002}{003}{004}{005}{006}{007}{008}" ascii wide
        $s3 = "::Unicode.GetString([System.Convert]::FromBase64String(" ascii wide
        
    condition:
        ($s1 in (0..100) or $s2 in (0..100))
        and $s3 in (filesize-200..filesize)
}
        