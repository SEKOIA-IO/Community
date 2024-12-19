rule infostealer_win_agrat {
    meta:
        id = "472effe8-5044-4ca1-88e0-3e19d445b9d1"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2022-06-01"
        classification = "TLP:CLEAR"
        
    strings:
        $str00 = "Vault.txt" wide
        $str01 = "Credman.txt" wide
        $str02 = "[Networks] {0}" wide
        $str03 = "[Screenshot] {0}" wide
        $str04 = "[Twitch] {0}" wide
        $str05 = "Servers.txt" wide
        $str06 = "[WindscribeVPN] {0}" wide
        $str07 = "[{0}] Thread finished!" wide
        $str08 = "[ERROR] Unable to enumerate vaults. Error (0x" wide
        $str09 = "snowflake-ssh" wide
        $str10 = "//setting[@name='Password']/value" wide
        $str11 = "MakeScreenshot" ascii
        
        $sys = "System.Collections.Generic.IEnumerator<Stealer." ascii
        
    condition:
        uint16(0)==0x5A4D and all of them and #sys > 10
}
        