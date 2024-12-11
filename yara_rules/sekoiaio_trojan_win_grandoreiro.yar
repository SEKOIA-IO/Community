rule sekoiaio_trojan_win_grandoreiro {
    meta:
        version = "1.0"
        description = "Finds Grandorerio samples based on the specific strings"
        source = "Sekoia.io"
        creation_date = "2022-08-24"
        id = "e48c86a1-e34f-4945-817a-9c85198a77bb"
        classification = "TLP:CLEAR"
        
    strings:
        $mut = "ZTP@11" wide
        
        $reg01 = "Software\\Embarcadero\\Locales" wide
        $reg02 = "Software\\CodeGear\\Locales" wide
        $reg03 = "Software\\Borland\\Locales" wide
        $reg04 = "Software\\Borland\\Delphi\\Locale" wide
        $reg05 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" wide
        
        $str01 = "SELECT * FROM AntiVirusProduct" wide
        $str02 = "GetTickCount64" wide
        $str03 = "C:\\Program Files (x86)\\Embarcadero\\Studio\\20.0\\lib\\Clever Internet Suite" wide
        $str04 = "{43826D1E-E718-42EE-BC55-A1E261C37BFE}" wide
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        