rule ransomware_win_chaos {
    meta:
        id = "c1876a18-0618-44e2-8919-b4a041de97e7"
        description = "Detects the Chaos Ransomware"
        author = "Sekoia.io"
        version = "1.0"
        creation_date = "2022-01-18"
        classification = "TLP:CLEAR"
        
    strings:
        $rep00 = "\\Desktop" wide
        $rep01 = "\\Links" wide
        $rep02 = "\\Contacts" wide
        $rep03 = "\\Documents" wide
        $rep04 = "\\Downloads" wide
        $rep05 = "\\Pictures" wide
        $rep06 = "\\Music" wide
        $rep07 = "\\OneDrive" wide
        $rep08 = "\\Saved Games" wide
        $rep09 = "\\Favorites" wide
        $rep10 = "\\Searches" wide
        $rep11 = "\\Videos" wide
        $rep12 = "C:\\Users\\" wide
        
        $str0 = "svchost.exe" wide
        $str1 = "\\privateKey.chaos" wide
        $str2 = "Chaos Ransomware" wide
        $str3 = "read_it.txt" wide
        $str4 = "<EncryptedKey>" wide
        $str5 = "passwordBytes" ascii
        $str6 = "lookForDirectories" ascii
        $str7 = "Rfc2898DeriveBytes" ascii
        $str8 = "ICryptoTransform" ascii
        $str9 = "FromBase64String" ascii
        
        $ext0 = ".torrent" wide
        $ext1 = ".ibank" wide
        $ext2 = ".wallet" wide
        $ext3 = ".swift" wide
        $ext4 = ".onetoc2" wide
        
    condition:
        uint16(0) == 0x5a4d and
    filesize > 50KB and filesize < 2MB and
        6 of ($str*) and 10 of ($rep*) and 4 of ($ext*)
}
        