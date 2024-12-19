rule apt_oilrig_webshell {
    meta:
        id = "53955117-5176-4682-89ad-1503faba42aa"
        version = "1.0"
        description = "Detects a webshell used by OilRig"
        author = "Sekoia.io"
        creation_date = "2024-10-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "string d = com;"
        $ = "string p = fu;"
        $ = "#@rt12!@$$$nnMF##"
        $ = "messi(d)))"
        
    condition:
        2 of them and filesize < 80KB
}
        