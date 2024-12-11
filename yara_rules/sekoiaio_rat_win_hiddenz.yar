rule sekoiaio_rat_win_hiddenz {
    meta:
        id = "4e582cda-4c50-4554-8e26-9d26206a02ee"
        version = "1.0"
        description = "Lazy rule to detect Hiddenz's HVNC sample based on te malware name contained in numerous samples"
        source = "Sekoia.io"
        creation_date = "2022-08-24"
        classification = "TLP:CLEAR"
        
    strings:
        $name0 = "Hiddenz's HVNC" wide ascii
        $name1 = "Hiddenzs_HVNC_DLL" wide ascii
        $name2 = "HiddenzHVNC" wide ascii
        
    condition:
        uint16(0)==0x5A4D and 1 of ($name*)
}
        