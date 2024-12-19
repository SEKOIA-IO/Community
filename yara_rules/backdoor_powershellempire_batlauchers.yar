rule backdoor_powershellempire_batlauchers {
    meta:
        id = "ad371665-ec59-45c8-9d99-2a675842c384"
        version = "1.0"
        description = "Detect BAT launchers for Empire"
        author = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "powershell -noP -sta -w 1 -enc  SQB" nocase wide ascii
        $ = "powershell -ep bypass -noP -sta -w 1 -enc SQB" nocase wide ascii
        $ = "-nol -nop -ep bypass \"[IO.File]::ReadAllText('%~f0')|iex" nocase wide ascii
        
    condition:
        any of them and filesize < 1MB
}
        