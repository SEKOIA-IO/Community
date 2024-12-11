rule sekoiaio_backdoor_powershellempire_gen {
    meta:
        id = "36050a5b-bdca-45cd-8e26-7129fdcbf1e8"
        version = "1.0"
        description = "Detects EmpirePowershell"
        source = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%{$J=($J+$S[$_]+$K[$_%$K.COUNt])%256;" nocase wide ascii
        $ = "($IV+$K))|IEX" nocase wide ascii
        
    condition:
        all of them and filesize < 1MB
}
        