rule sekoiaio_implant_win_havoc_default_strings {
    meta:
        version = "1.0"
        source = "Sekoia.io"
        description = "Finds Havoc implants based on the embedded default strings"
        creation_date = "2022-10-07"
        id = "955c2211-4502-4258-ba4c-0d96a5624283"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "C:\\Windows\\System32\\notepad.exe" ascii
        $str02 = "C:\\Windows\\SysWOW64\\notepad.exe" ascii
        $str03 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" ascii
        $str04 = "POST" wide
        $str05 = "\\??\\C:\\Windows\\System32\\ntdll.dll" wide
        $str06 = "X-Havoc: true" ascii
        $str07 = "X-Havoc-Agent: Demon" ascii
        $str08 = "/text.gif" ascii
        $str09 = "SeImpersonatePrivilege" ascii
        
    condition:
        uint16(0)==0x5A4D and 6 of them
}
        