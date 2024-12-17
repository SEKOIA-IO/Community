rule sekoiaio_apt_uta0218_upstyle_backdoor_strings {
    meta:
        id = "098fbad7-efaf-4198-83de-208c2ae16f89"
        version = "1.0"
        description = "Detects UPSTYLE backdoor"
        author = "Sekoia.io"
        creation_date = "2024-04-16"
        classification = "TLP:CLEAR"
        
    strings:
        $s1_1 = "f.write(b'''import base64;exec(base64.b64decode(b" ascii
        $s1_2 = "atime=os.path.getatime(" ascii
        
        $s2_1 = "exec(base64.b64decode(functioncode))"  ascii base64
        $s2_2 = "os.path.exists(systempth):" ascii base64
        $s2_3 = ".read().replace(b\"\\x00\",b\" \")" ascii base64
        
        $s3_1 = "if WRITE_FLAG:"  ascii base64
        $s3_2 = "re.search(SHELL_PATTERN"  ascii base64
        $s3_3 = "import threading,time,os,re,base64"  ascii base64
        
    condition:
        filesize < 1500 and
        (2 of ($s1_*) or 
        2 of ($s2_*) or 
        2 of ($s3_*) )
}
        