rule sekoiaio_apt_muddywater_powgoop_decoded {
    meta:
        id = "194cb9ef-da96-42b6-a3b5-b0aee7495f2c"
        version = "1.0"
        description = "Detects decoded PowGoop malware"
        author = "Sekoia.io"
        creation_date = "2022-01-13"
        classification = "TLP:CLEAR"
        
    strings:
        $h1 = "[System.Net.WebRequest]::Create(" ascii wide
        $h2 = "Headers.Add('Authorization'" ascii wide
        $h3 = "Headers.Add('Cookie',('value=' + $ec + ';')" ascii wide
        $h4 = ".GetResponse()" ascii wide
        $h5 = "GetResponseStream()" ascii wide
        $c1 = "return (65..90) + (97..122) | Get-Random -Count" ascii wide
        $c2 = "% {[char]$_}" ascii wide
        
    condition:
        filesize > 1KB and
        filesize < 1MB and
        ( $h2 in (@h1..@h5) and
        $h3 in (@h1..@h5) and
        $h4 in (@h1..@h5) )
        or ( $c2 in (@c1..@c1+50) ) and  true
}
        