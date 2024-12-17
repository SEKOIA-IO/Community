rule sekoiaio_apt_apt28_htmlsmuggling_disclosing_ip {
    meta:
        id = "57adc227-2b72-457e-a786-97ca1a7300d8"
        version = "1.0"
        reference = "https://www.zscaler.com/blogs/security-research/steal-it-campaign"
        description = "Detects some kind of HTMLSmuggling used by APT28"
        author = "Sekoia.io"
        creation_date = "2023-09-11"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "ipapi.co/json"
        $s2 = "a.download("
        $s3 = "a.click("
        
    condition:
        $s1 and $s2 and $s3 and filesize < 5000
}
        