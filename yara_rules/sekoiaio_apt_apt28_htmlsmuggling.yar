rule sekoiaio_apt_apt28_htmlsmuggling {
    meta:
        id = "2e20c992-d971-4c0f-99b3-a7d528c7055a"
        version = "1.0"
        reference = "https://www.zscaler.com/blogs/security-research/steal-it-campaign"
        description = "Detects some kind of HTMLSmuggling used by APT28"
        source = "Sekoia.io"
        creation_date = "2023-09-11"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "click();" ascii
        $s2 = "window.location.replace("
        
    condition:
        $s1 in (@s2..@s2-100)
}
        