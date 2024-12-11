import "pe"
        
rule sekoiaio_loader_win_truebot_dec22 {
    meta:
        version = "1.0"
        description = "Finds TrueBot DLL based on characteristic strings"
        source = "Sekoia.io"
        creation_date = "2022-12-12"
        id = "21e2c57c-8579-4312-b188-bc9171e37e5f"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "GetProcessWindowStation"
        $str1 = "GetUserObjectInformationW"
        $str2 = "GetLastActivePopup"
        $str3 = "GetActiveWindow"
        $str4 = "VirtualProtect"
        $str5 = "IsDebuggerPresent"
        
        $cle0 = "process call create \"powershell -executionpolicy bypass -nop -w hidden %s" ascii
        $cle1 = "%s\\%08x-%08x.ps1" ascii
        $cle2 = "POST %s HTTP/1.0" ascii
        $cle3 = "%s\\rundll32.exe" wide
        
    condition:
        uint16(0)==0x5A4D and (all of ($str*) or 1 of ($cle*))
        and (pe.exports("ChkdskExs") or pe.exports("fff"))
        and filesize < 1MB
}
        