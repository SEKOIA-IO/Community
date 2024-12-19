rule generic_php_webshell {
    meta:
        id = "415a96bd-11a4-40e7-8335-ac1f1a99d17c"
        version = "1.0"
        description = "Detects generic webshell"
        author = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "system($_POST['a']);"
        
    condition:
        all of them and filesize < 500
}
        