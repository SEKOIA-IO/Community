rule infostealer_win_pennywise_mar23 {
    meta:
        id = "9852b7e7-dfff-44e6-9068-d287cc84b069"
        version = "1.0"
        description = "Finds PennyWise samples based on strings"
        author = "Sekoia.io"
        creation_date = "2023-03-22"
        classification = "TLP:CLEAR"
        
    strings:
        $chr01 = "MvgmsudRT3loHygSj1F9K" ascii
        $chr02 = "WebInfidelity2023" ascii
        $chr03 = "PennyWise" ascii
        
        $str01 = "get_Handle" ascii
        $str02 = "get_Now" ascii
        $str03 = "get_Ticks" ascii
        $str04 = "set_Expect100Continue" ascii
        $str05 = "get_Jpeg" ascii
        $str06 = "set_UseShellExecute" ascii
        $str07 = "get_ProcessName" ascii
        $str08 = "get_UtcNow" ascii
        
    condition:
        uint16(0) == 0x5A4D and 1 of ($chr*) and 5 of ($str*)
}
        