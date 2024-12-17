rule sekoiaio_apt_tealkurma_snappytcp_strings {
    meta:
        id = "6bbee6d6-f490-4550-bd61-a643f93a8788"
        version = "1.0"
        description = "Detects TealKurma SnappyTCP shell script"
        author = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "#!/bin/bash" ascii
        $s2 = "2>&1>/dev/null&" ascii
        $s3 = "PATH=$PATH:$PWD;" ascii
        
    condition:
        $s1 at 0 and $s2 at filesize-16 and $s3 
        and filesize < 300
}
        