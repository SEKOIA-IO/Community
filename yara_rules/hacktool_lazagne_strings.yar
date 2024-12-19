rule hacktool_lazagne_strings {
    meta:
        id = "5a5e7a07-1252-48cc-ada5-46e796c4e00e"
        version = "1.0"
        description = "Detects LaZagne hacktool based on strings"
        author = "Sekoia.io"
        creation_date = "2022-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        
        $w1= "lazagne.softwares"
        $w2= "pypykatz.lsadecryptor"
        
        $l0= "PyModule_GetDict"
        $l1= "softwares.sysadmin.filezilla"
        $l2= "softwares.walle"
        $l3= "softwares.databases.sqldeveloper"
        $l4= "softwares.wifi.wpa_supplicant"
        
    condition:
        (uint32be(0) == 0x7f454c46 and all of ($l*))
        or (uint16be(0) == 0x4d5a and all of ($w*)) and
        filesize < 40MB
}
        