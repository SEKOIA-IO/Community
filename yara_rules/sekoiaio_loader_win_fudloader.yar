rule sekoiaio_loader_win_fudloader {
    meta:
        id = "4c2ac614-89af-4449-9fd2-9f935e4c27b8"
        version = "1.0"
        description = "Finds FUD-Loader samples based on specific strings"
        author = "Sekoia.io"
        reference = "https://github.com/0day2/FUD-Loader/"
        creation_date = "2023-09-25"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "set_WindowStyle" ascii
        $str02 = "set_FileName" ascii
        $str03 = "get_StartInfo" ascii
        $str04 = "GetRandomFileName" ascii
        $str05 = "DownloadFile" ascii
        $str06 = "GetTempPath" ascii
        $str07 = "ProcessStartInfo" ascii
        $str08 = "System.Diagnostics" ascii
        
    condition:
        uint16(0) == 0x5a4d and all of them and
        filesize < 10KB
}
        