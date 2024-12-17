rule sekoiaio_loader_latrodectus_dll {
    meta:
        version = "1.0"
        description = "Finds Latrodectus samples based on the specific strings"
        author = "Sekoia.io"
        reference = "https://twitter.com/Myrtus0x0/status/1732997981866209550"
        creation_date = "2023-12-08"
        id = "c60676ad-31cb-4f4d-9073-757a0ad7d23d"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "c:\\temp\\debug.pdb" fullword ascii
        $str02 = "Bottmp64.dll" fullword ascii
        $str03 = "scab" fullword ascii
        $str04 = "&wmic=" fullword ascii
        $str05 = "&ipconfig=" fullword ascii
        $str06 = "&systeminfo=" fullword ascii
        $str07 = "&domain_trusts=" fullword ascii
        $str08 = "&domain_trusts_all=" fullword ascii
        $str09 = "&net_view_all_domain=" fullword ascii
        $str10 = "&net_view_all=" fullword ascii
        $str11 = "&net_group=" fullword ascii
        $str12 = "&net_config_ws=" fullword ascii
        $str13 = "&net_wmic_av=" fullword ascii
        $str14 = "&whoami_group=" fullword ascii
        $str15 = "\"subproc\": [" fullword ascii
        $str16 = "&proclist=[" fullword ascii
        $str17 = "&desklinks=[" fullword ascii
        $str18 = "Update_%x" fullword wide
        $str19 = "Custom_update" fullword wide
        $str20 = "\\update_data.dat" fullword wide
        
    condition:
        uint16(0)==0x5A4D and 10 of them
}
        