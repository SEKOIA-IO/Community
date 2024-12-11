rule sekoiaio_backdoor_win_spacecolon {
    meta:
        id = "ae09f0e2-e913-44d5-abe1-715170368cc8"
        version = "1.0"
        description = "Finds Spacecolon samples based on specific strings (ScHackTool component)"
        source = "Sekoia.io"
        reference = "https://www.welivesecurity.com/en/eset-research/scarabs-colon-izing-vulnerable-servers/"
        creation_date = "2023-08-25"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Before Work" ascii
        $str02 = "DEFENDER OFF" ascii
        $str03 = "Stop Service" ascii
        $str04 = "Kill All (Default)" ascii
        $str05 = "Keyboard EN" ascii
        $str06 = "After Work" ascii
        $str07 = "Del Shadow Log" ascii
        $str08 = "Kill OSK" ascii
        $str09 = "PWGEN" ascii
        $str10 = "Character :" ascii
        $str11 = "PW GEN" ascii
        $str12 = "Cobian UI Pass" ascii
        $str13 = "Credssp" ascii
        $str14 = "Username :" ascii
        $str15 = "Password :" ascii
        $str16 = "TSpeedButton" ascii
        $str17 = "Ab1q2w3e!" ascii
        $str18 = "PC Details" ascii
        $str19 = "Mimi Dump" ascii
        $str20 = "MIMI Dump" ascii
        $str21 = "powershell -ExecutionPolicy Bypass -File \"" wide
        $str22 = "lastlog.txt" wide
        $str23 = "$AdminGroupName = (Get-WmiObject -Class Win32_Group -Filter 'LocalAccount = True AND SID = \"S-1-5-32-544\"').Name" wide
        $str24 = "net localgroup $AdminGroupName " wide
        
    condition:
        uint16(0) == 0x5a4d and 17 of them
}
        