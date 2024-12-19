rule apt_andariel_nestdoor_variants_strings {
    meta:
        id = "dcfc48ad-f17b-4224-912b-b01740080fea"
        version = "1.0"
        description = "Detects Nestdoor based on (weak) strings"
        author = "Sekoia.io"
        creation_date = "2024-06-17"
        classification = "TLP:CLEAR"
        
    strings:
        $v_11 = "Error occurs while reading" wide
        $v_12 = "{DECIMAL}" wide
        $v_13 = "lnk_" wide
        $v_21 = "Cannot connect with your ip and your operating system." wide
        $v_22 = "del /q /f %1" ascii
        $v_23 = "/f /tn %2" ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        (all of ($v_1*) or all of ($v_2*))
}
        