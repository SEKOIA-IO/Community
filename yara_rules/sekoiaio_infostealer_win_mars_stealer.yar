import "pe"
        
rule sekoiaio_infostealer_win_mars_stealer {
    meta:
        id = "3e2c7440b2fc9e4b039e6fa8152ac8fd"
        version = "1.0"
        description = "Detect Mars Stealer based on specific strings"
        source = "Sekoia.io"
        reference = "https://3xp0rt.com/posts/mars-stealer"
        creation_date = "2022-02-03"
        modification_date = "2022-02-14"
        classification = "TLP:CLEAR"
        
    strings:
        $dec = {a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 ??} //decryption op code
        
        $api00 = "LoadLibrary" ascii
        $api01 = "GetProcAddress" ascii
        $api02 = "ExitProcess" ascii
        $api03 = "advapi32.dll" ascii
        $api04 = "crypt32.dll" ascii
        $api05 = "GetTickCount" ascii
        $api06 = "Sleep" ascii
        $api07 = "GetUserDefaultLangID" ascii
        $api08 = "CreateMutex" ascii
        $api09 = "GetLastError" ascii
        $api10 = "HeapAlloc" ascii
        $api11 = "GetProcessHeap" ascii
        $api12 = "GetComputerName" ascii
        $api13 = "VirtualProtect" ascii
        $api14 = "GetUserName" ascii
        $api15 = "CryptStringToBinary" ascii
        
        $str0 = "JohnDoe" ascii
        //$str1 = "/c timeout /t 5 & del /f /q \"%s\" & exit" ascii
        //$str2 = "C:\\Windows\\System32\\cmd.exe" ascii
        
    condition:
        uint16(0)==0x5A4D and
        (#dec > 400 and
        12 of ($api*) and $str0) or
        for any i in ( 0..pe.number_of_sections-1 ) : (
            pe.sections[i].name == "LLCPPC" and pe.sections[i].raw_data_size < 5000 )
}
        