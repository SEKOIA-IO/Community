rule sekoiaio_apt_ta410_flowcloud_rtti {
    meta:
        id = "c6a18c08-8b98-46d7-a6c3-dc171c7791ac"
        version = "1.0"
        description = "Detects FlowCloud via RTTI"
        source = "Sekoia.io"
        creation_date = "2022-10-11"
        classification = "TLP:CLEAR"
        
    strings:
        $RTTI_1 = ".?AVdllloader@@" ascii fullword
        $RTTI_2 = ".?AVel_cryptowrapper@@" ascii fullword
        $RTTI_3 = ".?AVAntiVirusCheck@@" ascii fullword
        
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and all of them
}
        