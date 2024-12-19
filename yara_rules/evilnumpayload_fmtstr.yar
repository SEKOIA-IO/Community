rule evilnumpayload_fmtstr {
    meta:
        id = "980c58e4-e04d-4076-a92e-2c04ced19ece"
        version = "1.1"
        description = "Detect payload of EvilNum"
        author = "Sekoia.io"
        creation_date = "2022-07-25"
        classification = "TLP:CLEAR"
        
    strings:
        
        $fmtstr01 = "{\"v\":\"" ascii wide
        $fmtstr02 = ",\"u\":\"" ascii wide
        $fmtstr03 = ",\"a\":\"" ascii wide
        $fmtstr04 = ",\"w\":\"" ascii wide
        $fmtstr05 = ",\"d\":\"" ascii wide
        $fmtstr06 = ",\"n\":\"" ascii wide
        $fmtstr07 = ",\"r\":\"1\"" ascii wide
        $fmtstr08 = ",\"r\":\"0\"" ascii wide
        $fmtstr09 = ",\"xn\":\"" ascii wide
        $fmtstr10 = ",\"s\":0}" ascii wide
        $fmtstr11 = "{\"u\":\"" ascii wide
        $fmtstr12 = "\",\"sc\":1" ascii wide
        $fmtstr13 = ",\"dt\":\"" ascii wide
        
    condition:
        8 of ($fmtstr*)
}
        