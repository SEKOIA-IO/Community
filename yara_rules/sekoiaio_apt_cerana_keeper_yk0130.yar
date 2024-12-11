rule sekoiaio_apt_cerana_keeper_yk0130 {
    meta:
        id = "3da898a9-68e7-472f-8478-a0243840ec0a"
        version = "1.0"
        description = "Detects YK0130 reverse shell"
        source = "Sekoia.io"
        creation_date = "2024-10-04"
        classification = "TLP:CLEAR"
        hash = "2554e4864294dc96a5b4548dd42c7189"
        
    strings:
        $pdb = "C:\\Users\\admin\\source\\repos\\YK0130" ascii fullword
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them and filesize < 300KB
}
        