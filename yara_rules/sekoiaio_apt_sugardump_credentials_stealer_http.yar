rule sekoiaio_apt_sugardump_credentials_stealer_http {
    meta:
        id = "47d01ba8-9fdd-42d5-9f10-115f982dc133"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\\Google\\Chrome\\User Data" wide
        $ = "\\DebugLogWindowsDefender.txt" wide
        $ = "Opera Software\\Opera Stable" wide
        $ = "Microsoft\\Edge\\User Data" wide
        $ = "\"encrypted_key\":\"(.*?)\\" wide
        $ = "Url:" wide
        $ = "Username:" wide
        $ = "Password:" wide
        $ = "Application:" wide
        $ = "BCrypt.BCryptDecrypt" wide
        $ = "C:\\Users\\User\\" wide
        $ = "_CorExeMain"
        $ = "http://" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        10 of them
}
        