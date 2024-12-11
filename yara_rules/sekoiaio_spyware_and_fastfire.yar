rule sekoiaio_spyware_and_fastfire {
    meta:
        id = "93c0ffd5-faa5-4ead-8848-1c44b459dc29"
        version = "1.0"
        description = "Detect the FastFire malware"
        source = "Sekoia.io"
        creation_date = "2022-11-03"
        classification = "TLP:CLEAR"
        
    strings:
        $funct1 = {22 00 87 18 70 20 f3 ae 40 00 6e 10 f4 ae 00 00 0c 04 1f 04 16 19 13 00 28 23 6e 20 e3 ae 04 00 12 10 6e 20 e5 ae 04 00 1a 00 25 19 6e 20 ea ae 04 00 28 05 0d 00 6e 10 ef ae 00 00 6e 10 da ae 04 00 6e 10 e1 ae 04 00 0a 00 13 01 c8 00 32 10 20 00 1c 00 ea 17 6e 10 73 ad 00 00 0c 00 22 01 60 18 70 10 5d ae 01 00 1a 02 ff 50 6e 20 69 ae 21 00 6e 10 e1 ae 04 00 0a 04 6e 20 64 ae 41 00 6e 10 72 ae 01 00 0c 04 71 20 1d 09 40 00}
        $funct2 = {22 00 77 00 1a 01 88 56 70 20 f1 02 10 00 15 01 00 10 6e 20 f4 02 10 00 1a 01 80 8d 6e 20 32 ae 13 00 0a 01 38 01 0b 00 1a 01 25 76 71 10 b3 06 01 00 0c 01 6e 20 22 03 10 00 1a 01 56 61 6e 20 32 ae 13 00 0a 01 38 01 0b 00 1a 01 23 76 71 10 b3 06 01 00 0c 01 6e 20 22 03 10 00 1a 01 55 66 6e 20 32 ae 13 00 0a 03 38 03 0b 00 1a 03 24 76 71 10 b3 06 03 00 0c 03 6e 20 22 03 30 00 13 03 64 00 15 01 00 08 71 40 07 02 32 10 0c 03 11 03}
        $s0 = "TokenResult{token="
        $s1 = "[-] Send Resp Code ="
        $s2 = "/report_token/report_token.php?token="
        $s3 = "naver"
        $s4 = "daum"
        $s5 = "facebook"
        
    condition:
        uint32be(0)==0x6465780A
        and (1 of ($funct*) or all of ($s*))
}
        