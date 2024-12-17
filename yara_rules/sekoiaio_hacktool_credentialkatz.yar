rule sekoiaio_hacktool_credentialkatz {
    meta:
        id = "4795d131-2625-40ca-bca6-02aac5030b55"
        version = "1.0"
        description = "Finds ChromeKatz (CredentialKatz version) standalone samples based on the strings"
        author = "Sekoia.io"
        reference = "https://github.com/Meckazin/ChromeKatz"
        creation_date = "2024-10-30"
        classification = "TLP:CLEAR"
        hash = "2762e066128e186526c5ff272fc9184c0262d81d8c513e6515c25c189418931c"
        
    strings:
        $str01 = "Don't use your cat's name as a password!" ascii
        $str02 = "[-] Failed to parse command line argument /pid!" ascii
        $str03 = "[*] Targeting process: %ls on PID: %lu" ascii
        $str04 = "CredentialStore: NotSet" ascii
        $str05 = "CredentialStore: AccountStore" ascii
        $str06 = "CredentialStore: ProfileStore" ascii
        $str07 = "[*] Number of available credentials: %zu" ascii
        $str08 = "[+] Found browser process: %d" ascii
        $str09 = "Failed to read credential struct" wide
        $str10 = "Error reading right node" wide
        $str11 = "Failed to read the root node from given address" wide
        $str12 = "Error reading first node" wide
        $str13 = "chrome.dll" wide
        $str14 = "    Domain:" ascii
        $str15 = "    Password:" ascii
        $str16 = "Found %ls main process PID: %lu" ascii
        $str17 = "---------------" ascii
        $str18 = "CredentialKatz" ascii wide
        
    condition:
        uint16(0)==0x5A4D and 5 of them
}
        