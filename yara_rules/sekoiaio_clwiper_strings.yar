rule sekoiaio_clwiper_strings {
    meta:
        id = "91e531e2-8548-460f-88a8-cc09abb901e0"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2022-09-15"
        classification = "TLP:CLEAR"
        
    strings:
        $w1 = "missing args"
        $w2 = "wp starts"
        $w3 = "Total Bytez : %lld"
        $w4 = "percent is %f spent time is %.2fs"
        $d1 = "\\\\?\\RawDisk3"
        $d2 = "B4B615C28CCD059CF8ED1ABF1C71FE03C0354522990AF63ADF3C911E2287A4B906D47D"
        
    condition:
        uint16be(0) == 0x4d5a and
        (3 of ($w*) or all of ($d*))
}
        