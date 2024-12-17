rule sekoiaio_infostealer_win_daolpu_str {
    meta:
        id = "dde1cf12-48d8-45b6-b453-b7196e6b1271"
        version = "1.0"
        description = "Finds Daolpu Stealer samples based on specific strings."
        author = "Sekoia.io"
        reference = "https://www.crowdstrike.com/blog/fake-recovery-manual-used-to-deliver-unidentified-stealer/"
        creation_date = "2024-07-23"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Content-Type: %s%s%s" ascii
        $str02 = "Content-Disposition: %s%s%s%s%s%s%s" ascii
        $str03 = "\\CocCoc\\Browser\\User Data\\Local State" ascii
        $str04 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii
        $str05 = "\\Mozilla\\Firefox\\Profiles" ascii
        $str06 = "No MAC Address Found" ascii
        $str07 = "C:\\Windows\\Temp\\" ascii
        $str08 = "C:\\Windows\\Temp\\result.txt" ascii
        $str09 = "Privatekey@2211#$" ascii
        $str10 = "CryptStringToBinaryA Failed to convert BASE64 private key." ascii
        $str11 = "taskkill /F /IM chrome.exe" ascii
        
    condition:
        uint16(0)==0x5A4D and 8 of them
}
        