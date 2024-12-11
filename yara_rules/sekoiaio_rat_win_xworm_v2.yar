rule sekoiaio_rat_win_xworm_v2 {
    meta:
        version = "1.0"
        description = "Finds XWorm v2 samples based on characteristic strings"
        source = "Sekoia.io"
        reference = "https://blog.cyble.com/2022/08/19/evilcoder-project-selling-multiple-dangerous-tools-online/"
        creation_date = "2022-11-07"
        id = "6cf06f52-0337-415d-8f29-f63d67e228f8"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "XWorm.exe" wide ascii
        $str02 = "ngrok" wide ascii
        $str03 = "Mutexx" ascii
        $str04 = "FileManagerSplitFileManagerSplit" wide
        $str05 = "InstallngC" wide
        $str06 = "downloadedfile" wide
        $str07 = "creatfile" wide
        $str08 = "creatnewfolder" wide
        $str09 = "showfolderfile" wide
        $str10 = "hidefolderfile" wide
        $str11 = "txtttt" wide
        $str12 = "\\root\\SecurityCenter2" wide
        $str13 = "[USB]" wide
        $str14 = "[Drive]" wide
        $str15 = "[Folder]" wide
        $str16 = "HVNC" wide
        $str17 = "http://exmple.com/Uploader.php" wide
        $str18 = "XKlog.txt" wide
        $str19 = "Select * from AntivirusProduct" wide
        $str20 = "runnnnnn" wide
        $str21 = "RunBotKiller" wide
        $str22 = "bypss" wide
        $str23 = "<Xwormmm>" wide
        
    condition:
        uint16(0)==0x5A4D and 12 of them
}
        