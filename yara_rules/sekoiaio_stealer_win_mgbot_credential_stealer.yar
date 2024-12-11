rule sekoiaio_stealer_win_mgbot_credential_stealer {
    meta:
        id = "e06501c1-c842-43f7-a429-9026bc0a4fd4"
        version = "1.0"
        description = "Detect MgBot credential stealer plugin"
        source = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        hash1 = "174a62201c7e2af67b7ad37bf7935f064a379f169cf257ca16e912a46ecc9841"
        hash2 = "cb7d9feda7d8ebfba93ec428d5a8a4382bf58e5a70e4b51eb1938d2691d5d4a5"
        reference = "https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/"
        
    strings:
        $ = "Software\\Aerofox\\Foxmail\\Indenties" wide
        $ = "Software\\Aerofox\\FoxmailPreview" wide
        $ = "IMAP Password" wide
        $ = "POP3 Password" wide
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        