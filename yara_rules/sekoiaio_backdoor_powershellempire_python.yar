rule sekoiaio_backdoor_powershellempire_python {
    meta:
        id = "c2913f60-46a2-42c1-8569-72568eaddaed"
        version = "1.0"
        description = "Detects Empire Python version"
        author = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "import sys,base64;exec"
        $ = "aW1wb3J0IHN5cztpbXBvcnQgcmUsIHN1YnByb2"
        
    condition:
        all of them and filesize < 1MB
}
        