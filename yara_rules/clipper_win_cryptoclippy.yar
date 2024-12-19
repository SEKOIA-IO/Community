rule clipper_win_cryptoclippy {
    meta:
        id = "eaa98a8e-e29e-43a4-8b2d-2137d33d4116"
        version = "1.0"
        description = "Finds CryptoClippy samples"
        author = "Sekoia.io"
        reference = "https://unit42.paloaltonetworks.com/crypto-clipper-targets-portuguese-speakers/"
        creation_date = "2023-04-11"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "C:\\mbedtls\\library\\" ascii
        $str02 = "udp://8.8.8.8:53" ascii
        $str03 = "Upgrade: websocket" ascii
        $str04 = "%s\\%s.lnk" ascii
        $str05 = "%s\\%s.ps1" ascii
        $str06 = "%s\\%s.bat" ascii
        $str07 = "set PSExecutionPolicyPreference=Unrestricted" ascii
        $str08 = "schtasks /delete /tn \"%ls\" /f" ascii
        $str09 = "SetClipboardData" ascii
        $str10 = "SetWinEventHook" ascii
        
    condition:
        uint16(0) == 0x5A4D and 8 of them
}
        