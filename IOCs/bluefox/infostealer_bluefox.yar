rule infostealer_win_bluefox {
    meta:
        malware = "BlueFox"
        description = "Find BlueFox Stealer v2 samples based on the specific strings embed in the executable files"
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/bluefox-stealer-a-newcomer-designed-for-traffers-teams/"
        classification = "TLP:CLEAR"

    strings:
        $str01 = "DesktopScreenshotLength" ascii
        $str02 = "SoftwareSearchesCount" ascii
        $str03 = "AutoCompleteLength" ascii
        $str04 = "DesktopSizeLength" ascii
        $str05 = "CPULength" ascii
        $str06 = "GPUsLength" ascii
        $str07 = "FullNameLength" ascii
        $str08 = "Asn1NssLength" ascii
        $str09 = "LoginLength" ascii
        $str10 = "BrowserCount" ascii

    condition:
        uint16(0)==0x5A4D and 9 of them
}
