rule sekoiaio_infostealer_win_vidar_str_jul22 {
    meta:
        id = "1dc18694-aaac-41e6-979a-c06d5d62f5ea"
        version = "1.0"
        description = "Detect the Vidar infostealer based on specific strings"
        source = "Sekoia.io"
        creation_date = "2022-07-26"
        modification_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "vcruntime140.dll" ascii
        $str02 = "\\screenshot.jpg" ascii
        $str03 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor" ascii
        $str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $str05 = "%s\\%s\\%s\\chrome-extension_%s_0.indexeddb.leveldb" ascii
        $str06 = "\\CC\\%s_%s.txt" ascii
        $str07 = "\\Autofill\\%s_%s.txt" ascii
        $str08 = "\\History\\%s_%s.txt" ascii
        $str09 = "\\Downloads\\%s_%s.txt" ascii
        $str10 = "Content-Disposition: form-data; name=" ascii
        $str11 = "Exodus\\exodus.wallet" ascii
        $str12 = "*%DRIVE_REMOVABLE%*" ascii
        
        $opc = {55 8b ec 51 56 8b 75 ?? 33 c0 c7 46 14 ?? ?? ?? ?? 89 46 ?? 68 ?? ?? ?? ?? 8b ce 89 45 ?? 88 06 e8 1f b6 ff ff 8b c6 5e c9 c2 ?? ??}
        
    condition:
        uint16(0)==0x5A4D and (7 of them or $opc)
}
        