rule sekoiaio_apt_kimsuky_sharpext_jsexfil_strings {
    meta:
        id = "c9ebd123-6450-4424-93d1-60322bd97bf6"
        version = "1.0"
        description = "Detects the exfiltration JS code of SharpExt"
        author = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "var req_url" ascii fullword
        $ = "var newReqId" ascii fullword
        $ = "chrome.tabs.query" ascii fullword
        $ = "payload.message.flags = new Object();" ascii fullword
        
    condition:
        all of them and filesize < 50KB
}
        