rule sekoiaio_apt_apt28_ukrnet_phishing_page {
    meta:
        id = "053158d8-aac0-486f-8432-834a06f41ed2"
        version = "1.0"
        description = "Detects APT28 Phishing page"
        source = "Sekoia.io"
        creation_date = "2024-09-02"
        classification = "TLP:CLEAR"
        hash = "20dc3a5beb8e3a7801e010b4113efef1"
        hash = "5f1462144d7704101cd71c679ea0322b"
        
    strings:
        $ = "baseurl+\"/captcha\""
        $ = "(\"sessionID\", sessionID"
        $ = ".responseJSON['origin"
        $ = "var baseurl="
        $ = "(req.responseText.includes("
        $ = "else if (req.responseText=='FAIL')"
        $ = "|| document.getElementById('confpwd"
        $ = "/master/dist/text-security-disc.woff"
        
    condition:
        4 of them and filesize < 500KB
}
        