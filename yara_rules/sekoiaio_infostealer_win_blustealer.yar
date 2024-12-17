rule sekoiaio_infostealer_win_blustealer {
    meta:
        version = "1.0"
        description = "Detect the BluStealer infostealer based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2022-10-05"
        id = "a56b3c12-9d83-4a0b-81e8-43332e64d599"
        classification = "TLP:CLEAR"
        
    strings:
        $cha01 = "@top\\LOGGERS\\DARKCLOUD" wide
        $cha02 = "===============DARKCLOUD===============" wide
        $cha03 = "#######################################DARKCLOUD#######################################" wide
        $cha04 = "fireballsabadafirebricksfisherboat" ascii
        $cha05 = "Moonchild Pro2ductions" wide
        
        $str01 = "\\Microsoft\\Windows\\Templates\\credentials.txt" wide
        $str02 = "\\NETGATE Technologies\\BlackHawK\\Profiles" wide
        $str03 = "SysWOW64\\winsqlite3.dll" wide
        $str04 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*RD_" wide
        $str05 = "Expiry Date;" wide
        $str06 = "SELECT c0subject, c3author, c4recipients, c1body  FROM messagesText_content" wide
        $str07 = "http://www.mediacollege.com/internet/utilities/show-ip.shtml" wide
        $str08 = "\\163MailContacts.txt" wide
        $key_0  = {ba ?? ?? 40 00 8d 4?}
        
    condition:
        uint16(0)==0x5A4D and 2 of ($cha*) and 4 of ($str*) and $key_0
}
        