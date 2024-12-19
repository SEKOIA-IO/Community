rule apt_implant_xdealer_vbs_launcher_strings {
    meta:
        id = "ebfc8a33-70dc-44d5-bc4a-07afc56f8254"
        version = "1.0"
        description = "Detects XDealer VBS Launcher"
        author = "Sekoia.io"
        creation_date = "2024-03-22"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Dim objws"
        $s2 = "Set objws="
        $s3 = "objws.Run \"\"\"C:\\ProgramData\\"
        
    condition:
       $s1 at 0 and all of them and filesize < 200
}
        