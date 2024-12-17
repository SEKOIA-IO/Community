rule sekoiaio_rat_win_remcos {
    meta:
        id = "011132f5-c5d9-4e97-bfed-0b94c9a30481"
        version = "1.0"
        description = "DEPRECATED : Find Remcos RAT samples based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-01-29"
        modification_date = "2024-01-08"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" ascii
        $str02 = "Disconnection occurred, retrying to connect..." ascii
        $str03 = "[Following text has been pasted from clipboard:]" ascii
        $str04 = "[Following text has been copied to clipboard:]" ascii
        $str05 = "[Chrome StoredLogins found, cleared!]" ascii
        $str06 = "PING 127.0.0.1 -n 2" ascii
        $str07 = "Remcos_Mutex_Inj" ascii
        $str08 = " * REMCOS v" ascii
        $str09 = "Connected to C&C!" ascii
        $str10 = "[Cleared all cookies & stored logins!]" ascii
        
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
        