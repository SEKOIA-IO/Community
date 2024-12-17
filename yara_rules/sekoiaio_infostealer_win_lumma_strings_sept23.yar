rule sekoiaio_infostealer_win_lumma_strings_sept23 {
    meta:
        version = "1.0"
        description = "Finds Lumma samples based on the specific strings"
        author = "Sekoia.io"
        creation_date = "2023-09-14"
        modification_date = "2023-10-31"
        id = "45900760-c10d-40c0-a49a-c66358a8a66a"
        classification = "TLP:CLEAR"
        
    strings:
        $str10 = "CryptStringToBinaryA" ascii
        $str11 = "WinHttpQueryDataAvailable" ascii
        $str12 = "GetComputerNameExA" ascii
        $str13 = "GetCurrentHwProfileW" ascii
        $str14 = "ntdll.dll" wide
        //$str15 = "%appdata%\\Thunderbird\\Profiles" wide
        $str16 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h" wide
        $str17 = "xxxxxxxxxxx" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        