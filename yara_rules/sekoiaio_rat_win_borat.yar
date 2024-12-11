rule sekoiaio_rat_win_borat {
    meta:
        id = "9f8badb3-ee8b-45d9-8515-c847351bb1f5"
        version = "1.0"
        description = "Detect the Borat RAT besed on specific strings"
        source = "Sekoia.io"
        creation_date = "2022-04-08"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "BoratRatMutex_Sa8XOfH1BudX" ascii
        $str1 = "BoratRat.exe" ascii
        $str2 = "BoratRat" ascii
        $str3 = "CN=BoratRat" wide
        $str4 = "Sending plugun to " wide
        $str5 = "Save recorded file fail " wide
        $str6 = "Sa8XOfH1BudX" wide
        $str7 = "Alert when process activive." wide
        $str8 = "disableDefedner" wide
        $str9 = "bin\\Ransomware.dll" wide
        $str10 = "disableDefedner" wide
        
    condition:
        uint16(0)==0x5A4D and 7 of them
}
        