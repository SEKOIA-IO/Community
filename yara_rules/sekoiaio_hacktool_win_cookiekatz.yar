rule sekoiaio_hacktool_win_cookiekatz {
    meta:
        id = "a32769bb-4ec4-46c7-9402-21afdf8d4293"
        version = "1.0"
        description = "Finds ChromeKatz (CookieKatz version) standalone samples based on the strings"
        author = "Sekoia.io"
        reference = "https://github.com/Meckazin/ChromeKatz"
        creation_date = "2024-10-30"
        classification = "TLP:CLEAR"
        hash = "fef9fc33a788489af44b2f732c450d4ef018fbaced7f5471230b282dfd6f1169"
        
    strings:
        $str01 = "CookieKatz.exe" ascii
        $str02 = "--utility-sub-type=network.mojom.NetworkService" wide
        $str03 = "chrome.dll" wide
        $str04 = "msedge.dll" wide
        $str05 = "msedgewebview2.exe" wide
        $str06 = "Failed to read cookie struct" wide
        $str07 = "Failed to read the root node from given address" wide
        $str08 = "Error reading left node" wide
        $str09 = "By Meckazin" ascii
        $str10 = "By default targets first available Chrome process" ascii
        $str11 = "Kittens love cookies too!" ascii
        $str12 = "Attempting to read the cookie value from address: 0x%p" ascii
        $str13 = "szCookieMonster" ascii
        $str14 = "[*] Targeting Chrome" ascii
        $str15 = "[*] Targeting Edge" ascii
        $str16 = "[*] This Cookie map was empty" ascii
        $str17 = "[+] Found browser process: %d" ascii wide
        $str18 = "[*] Targeting process PID: %d" wide
        $str19 = "[*] Found CookieMonster on 0x%p" wide
        $str20 = "[*] CookieMap should be found in address 0x%p" wide
        
    condition:
        uint16(0)==0x5A4D and 8 of them
}
        