rule sekoiaio_ransomware_win_voidcrypt {
    meta:
        id = "394033cc-20fe-4ced-8d77-5f1061bb8c96"
        version = "1.0"
        description = "Detect the Limbozar / VoidCrypt ransomware"
        author = "Sekoia.io"
        creation_date = "2021-10-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "C:\\ProgramData\\pkey.txt" ascii
        $s2 = "C:\\ProgramData\\IDk.txt" ascii
        $s3 = "fuckyoufuckyoufuckyoufuckyou" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        