rule sekoiaio_guloader_powershell_1 {
    meta:
        id = "28c68991-db8b-4f00-b3a3-17286418a4ed"
        version = "1.0"
        description = "Powershell downloading decoy and delivering GuLoader"
        source = "Sekoia.io"
        creation_date = "2024-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "powershell -win hidden"
        $s2 = "=iex($"
        $s3 = ".Replace('"
        $s4 = "$(Get-ChildItem -Include *.lnk -Name));"
        
    condition:
        all of them and filesize < 10KB and #s3 > 3
}
        