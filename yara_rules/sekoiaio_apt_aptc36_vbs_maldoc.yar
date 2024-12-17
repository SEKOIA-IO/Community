rule sekoiaio_apt_aptc36_vbs_maldoc {
    meta:
        id = "f0ca061f-e94b-4f70-bbd1-8a15193652d3"
        version = "1.0"
        description = "Find VBS file used by the threat actor APT-C-36"
        author = "Sekoia.io"
        creation_date = "2022-02-16"
        classification = "TLP:CLEAR"
        
    strings:
        $dim = "dim " wide ascii
        $hea = "::::::::::::::::::::::::::::::::::::::::::::::::" wide ascii
        $str0 = "update" wide ascii nocase
        $str1 = "On Error Resume Next" wide ascii
        $str2 = "CreateObject" wide ascii
        $str3 = "WScript" wide ascii
        
    condition:
        #dim > 5 and
        #hea > 10 and
        2 of ($str*) and
        filesize > 10KB and filesize < 1MB
}
        