rule ransomware_win_karma {
    meta:
        id = "efd87a17-7c99-404a-8ea6-2f5c2121f9f2"
        version = "1.0"
        description = "Detect the Karma ransomware payload"
        author = "Sekoia.io"
        creation_date = "2021-08-25"
        classification = "TLP:CLEAR"
        
    strings:
        $a1 = "KARMA" ascii
        
        $u1 = "KARMA" wide
        $u2 = "-ENCRYPTED.txt" wide
        $u3 = "Encrypting directory:" wide
        $u4 = "Encrypting file:" wide
        $u5 = "Trying to import ECC public key..." wide
        
    condition:
        uint16(0)==0x5A4D and filesize < 150KB and all of them
}
        