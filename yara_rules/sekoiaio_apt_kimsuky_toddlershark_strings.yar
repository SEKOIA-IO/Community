rule sekoiaio_apt_kimsuky_toddlershark_strings {
    meta:
        id = "2db1a424-9e83-4168-8ebf-d3b415b6a576"
        version = "1.0"
        description = "Detects Kimsuky TODDLERSHARK vbs malware"
        author = "Sekoia.io"
        creation_date = "2024-03-06"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "On Error Resume Next"
        $ = ".open \"POST\", \"http"
        $ = ".setRequestHeader"
        $ = ".send"
        $ = "Execute("
        $ = ".responseText)"
        
    condition:
        all of them and filesize < 450
}
        