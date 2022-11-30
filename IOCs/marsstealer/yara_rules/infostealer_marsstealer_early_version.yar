rule infostealer_win_mars_stealer_early_version {
    meta:
        description = "Identifies samples of Mars Stealer early version based on opcodes of the function loading obfuscated strings."
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/mars-a-red-hot-information-stealer/"
        classification = "TLP:WHITE"
        hash = "7da3029263bfbb0699119a715ce22a3941cf8100428fd43c9e1e46bf436ca687"

    strings:
        $dec = {a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 ??}

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

    condition:
        uint16(0)==0x5A4D and
        #dec > 400 and 12 of ($api*) and $str0
}
