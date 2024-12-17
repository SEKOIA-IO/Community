rule sekoiaio_apt_badmagic_listfiles_pshscript {
    meta:
        id = "55f1c409-234e-4feb-91a3-9bf5c41ec2b8"
        version = "1.0"
        description = "Detects BadMagic ListFiles powershell script"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$env:USERPROFILE"
        $ = "-Include *.jpg, *.odt, *.doc, *.docx"
        
    condition:
        all of them and filesize < 1KB
}
        