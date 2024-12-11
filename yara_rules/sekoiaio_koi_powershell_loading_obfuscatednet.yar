rule sekoiaio_koi_powershell_loading_obfuscatednet {
    meta:
        id = "75a7460d-cc28-470e-9841-da8e46ee0101"
        version = "1.0"
        description = "Powershell script loading obfuscated .NET Koi module"
        source = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "# [Net.ServicePointManager]::SecurityProtocol +='tls12'"
        $s2 = "$binary[$i] = $binary[$i] -bxor $k[$i % $k.Length]"
        $s3 = "\").Split('|')"
        $s4 = "$ep.Invoke($null, "
        
    condition:
        $s3 and 3 of them
}
        