rule sekoiaio_infostealer_win_solarmarker_dll {
    meta:
        version = "1.0"
        description = "Finds SolarMarker DLL based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2022-12-09"
        id = "a2fe7f09-7134-4054-ba40-5ea66785a26c"
        classification = "TLP:CLEAR"
        
    strings:
        $zka = "zkabsr" wide
        
        $str0 = "set_PersistKeyInCsp" ascii
        $str1 = "get_IV" ascii
        $str2 = "get_MachineName" ascii
        $str3 = "get_Current" ascii
        $str4 = "ps_script" ascii
        $str5 = "request_data" ascii
        $str6 = "WindowsBuiltInRole" ascii
        $str7 = "DllImportAttribute" ascii
        $str8 = "get_BlockSize" ascii
        $str9 = "GetRequestStream" ascii
        
    condition:
        uint16(0)==0x5A4D and
        (($zka and 3 of ($str*)) or (all of ($str*)))
        and filesize < 1MB
}
        