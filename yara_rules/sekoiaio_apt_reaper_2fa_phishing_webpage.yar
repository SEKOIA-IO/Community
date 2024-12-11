rule sekoiaio_apt_reaper_2fa_phishing_webpage {
    meta:
        id = "348ca2ad-c8f9-4aed-8a27-95caa3a34f4b"
        version = "1.0"
        description = "Detects Reaper 2FA phishing webpage"
        source = "Sekoia.io"
        creation_date = "2023-03-09"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "setTimeout(checkUpload,"
        $ = "commChannel.addListener("
        $ = "else if(commType =="
        $ = "?dir=DOWN&method=READ&id="
        $ = "Content : base64_encode(upload_data)"
        $ = "$.post(upHttpRelayer"
        $ = "var ablyUpData = {"
        $ = "initComm();"
        $ = "function Next(arg) {"
        
    condition:
        3 of them
}
        