import "pe"
        
rule sekoiaio_infostealer_win_irontiger_chrome_stealer {
    meta:
        id = "8c5c3ed0-e1ea-4079-b330-ace8724bff2a"
        version = "1.0"
        description = "Detect the chrome_stealer malware"
        author = "Sekoia.io"
        creation_date = "2023-03-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "passwords.txt"
        $ = "CryptUnprotectData: 0x%08x"
        $ = "cookies.txt"
        $ = "decrypt to %s"
        $ = ".\\chromedb_tmp" wide ascii
        $ = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS;"
        $ = "decrypt successful!"
        $ = "url: %s"
        $ = "user: %s"
        $ = "pass: %s"
        $ = "aes key:"
        $ = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide
        $ = "password file %s" wide
        $ = "cookies file %s" wide
        $ = "keyfile: %s" wide
        
    condition:
        (uint16(0)==0x5A4D and all of them)
        or pe.imphash() == "e862f5a6671f9dbd6f53d3d557e568f0"
}
        