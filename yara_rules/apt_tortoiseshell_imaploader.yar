rule apt_tortoiseshell_imaploader {
    meta:
        id = "e1706b59-5c94-4fbf-8560-0022ca631d1d"
        version = "1.0"
        description = "Detects IMAPLoader malware"
        author = "Sekoia.io"
        creation_date = "2023-11-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "yandex.com"
        $s2 = "saveImapMessage.pdb"
        $s3 = "downloader"
        $s4 = "MailServer.Auth"
        
    condition:
        filesize < 1MB and
        3 of them
}
        