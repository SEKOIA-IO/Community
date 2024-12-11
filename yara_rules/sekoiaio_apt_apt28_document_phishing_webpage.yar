rule sekoiaio_apt_apt28_document_phishing_webpage {
    meta:
        id = "585a8e23-c302-41d3-938f-eda60c82ef28"
        version = "1.0"
        description = "Detects APT28 document phishing webpage"
        source = "Sekoia.io"
        creation_date = "2024-04-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "webhook.site"
        $ = "document.createElement('img')"
        $ = "brightness(15%) blur(7.0px)"
        $ = "This document is not available from mobile devices."
        $ = "Capture2.PNG"
        $ = ">CLICK TO VIEW DOCUMENT<"
        $ = "window.location.href = 's"
        $ = ".oast."
        
    condition:
        4 of them and filesize < 20KB
}
        