rule sekoiaio_hacktool_win_processhacker {
    meta:
        version = "1.0"
        description = "Detect ProcessHacker hacktool"
        author = "Sekoia.io"
        creation_date = "2022-09-09"
        id = "1dffe8c9-2ab7-4265-965e-8673b80f17d5"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "Unable to uninstall KProcessHacker" wide
        $str1 = "Process Hacker's settings file is corrupt. Do you want to reset it?" wide
        $str2 = "Process Hacker uses the following components:" wide
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        