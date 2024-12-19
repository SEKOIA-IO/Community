rule apt_gamaredon_ddrdoh_powershell_backdoor {
    meta:
        id = "3413dedd-e3ec-4231-8af7-c7f709ab82d7"
        version = "1.0"
        description = "Detects GAMAREDON's DDRDOH PowerShell Backdoor"
        author = "Sekoia.io"
        creation_date = "2023-01-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "hidden iex $env:" ascii wide
        $ = ".substring(0,4) -eq \"http" ascii wide
        $ = ".split('!')[1];" ascii wide
        $ = " -bxor $key[$i % $key.Length]" ascii wide
        $s = "Filter $fil | Select-Object VolumeSerialNumber" ascii wide
        
    condition:
        uint8(0) == 0x24 and 4 of them and filesize < 10KB
}
        