rule sekoiaio_apt_kimsuky_sharpext_devps1_strings {
    meta:
        id = "f2ad32a4-bfca-40b2-964e-b8562538a6f2"
        version = "1.0"
        description = "Detects strings of Dev.ps1"
        author = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "keybd_Event(" ascii fullword
        $s2 = "Sleep" ascii fullword
        $s3 = "CreateDev" ascii fullword
        
    condition:
        filesize < 10KB and 
        #s1 == 6 and #s2 == 6 and $s3
}
        