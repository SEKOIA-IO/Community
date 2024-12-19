rule apt_uac0154_powershell_infection_chain_2 {
    meta:
        id = "6fe37d52-9bd3-4aa8-83ba-15399bd1b66c"
        version = "1.0"
        description = "UAC-0154 Infection chain"
        author = "Sekoia.io"
        creation_date = "2023-10-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "files.catbox.moe"
        $ = "$pse = $pse.Replace"
        $ = "start -WindowStyle Hidden -FilePath $p"
        $ = "-bxor $xorMask"
        $ = "SysctlHost"
        
    condition:
        4 of them and filesize < 100KB
}
        