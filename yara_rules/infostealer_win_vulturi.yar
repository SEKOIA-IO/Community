rule infostealer_win_vulturi {
    meta:
        id = "5369cbfb-ff94-4484-b5a4-894feeed97e1"
        version = "1.0"
        description = "Detect the Vulturi infostealer based on specific strings"
        author = "Sekoia.io"
        reference = "https://lamp-ret.club/t/vulturi-cracked-by-tr0uble-and-eshelon_mayskih.193/"
        creation_date = "2022-03-14"
        classification = "TLP:CLEAR"
        
    strings:
        $vul = "Vulturi_" ascii
        
        $str01 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A" wide
        $str02 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" wide
        $str03 = "Apps\\Gaming\\Minecraft" wide
        $str04 = "Apps\\Gaming\\Steam\\Apps" wide
        $str05 = "Messengers\\Facebook\\Contacts.txt" wide
        $str06 = "Messengers\\Discord\\Tokens.txt" wide
        $str07 = "Apps\\VPN\\NordVPN\\accounts.txt" wide
        $str08 = "Apps\\VPN\\DUC\\credentials.txt" wide
        $str09 = "System\\Screenshots\\Webcam.png" wide
        $str10 = "System\\Screenshots\\Desktop.png" wide
        $str11 = "GTA San Andreas User Files\\SAMP\\USERDATA.DAT" wide
        $str12 = "http://ip-api.com/line?fields=query" wide
        $str13 = "Wireshark" wide
        $str14 = "KeePass.config.xml" wide
        $str15 = "Apps\\TheBat!" wide
        $str16 = "Vulturi" wide
        $str17 = "StealerStub" wide
        
    condition:
        uint16(0)==0x5A4D and
        (#vul > 50 or 12 of ($str*))
}
        