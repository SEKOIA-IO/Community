rule sekoiaio_ransomware_win_wing {
    meta:
        id = "c2fe8321-8013-4aa4-91a6-c0face3e6b52"
        version = "1.0"
        description = "Finds Wing ransomware samples based on specific strings"
        source = "Sekoia.io"
        creation_date = "2024-01-30"
        classification = "TLP:CLEAR"
        
    strings:
        $fun01 = "LockBIT" ascii fullword
        $fun02 = "BigEncrypt" ascii
        $fun03 = "RunEncrypt" ascii
        $fun04 = "AesEncrypt" ascii
        $fun05 = "KeyGenerator" ascii
        $fun06 = "GetUniqueKey" ascii
        $fun07 = "SearchFolder" ascii
        $fun08 = "ThreadFolders" ascii
        $fun09 = "ContainsKeyword" ascii
        $fun10 = "ReadMeMaker" ascii
        $fun11 = "StopAndConfigureSqlServices" ascii
        $fun12 = "WipeRecycleBin" ascii
        $fun13 = "TelSender" ascii
        
        $str01 = "AnyDesk" wide
        $str02 = "firebird" wide
        $str03 = "Acronis" wide
        $str04 = "config \"" wide
        $str05 = " start= demand" wide
        $str06 = "' stopped and configured to start automatically." wide
        $str07 = "Error processing service '" wide
        $str08 = "$RECYCLE.BIN" wide
        $str09 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $str10 = "UniqueID:" wide
        $str11 = "PersonalID:" wide
        
        $ran01 = "C:\\Readme.txt" wide
        $ran02 = "C:\\LockBIT\\systemID" wide
        $ran03 = "Your system has been encrypted by our team, and your files have been locked using our proprietary algorithm !" wide
        $ran04 = "* Please read this message carefully and patiently *" wide
        $ran05 = "* If you use any tools, programs, or methods to recover your files and they get damaged, we will not be responsible for any harm to your files !" wide
        $ran06 = "* Note that your files have not been harmed in any way they have only been encrypted by our algorithm." wide
        $ran07 = "Your files and your entire system will return to normal mode through the program we provide to you. No one but us will be able to decrypt your files !" wide
        $ran08 = "* To gain trust in us, you can send us a maximum of 2 non-important files, and we will decrypt them for you free of charge." wide
        $ran09 = "Please put your Unique ID as the title of the email or as the starting title of the conversation." wide
        $ran10 = "* For faster decryption, first message us on Telegram. If there is no response within 24 hours, please email us *" wide
        
    condition:
        uint16(0) == 0x5a4d and
        ((5 of ($fun*) and 5 of ($str*) and 2 of ($ran*)) or
        12 of ($fun*) or 10 of ($ran*) or 8 of ($ran*))
}
        