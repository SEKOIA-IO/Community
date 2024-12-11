rule sekoiaio_backdoor_lin_bpfdoor {
    meta:
        id = "1776ff6f-6fbb-4a81-bcad-c43b5117c67c"
        version = "1.0"
        description = "Detect the BPFDoor backdoor used by the Chinese TA Red Menshen"
        source = "Sekoia.io"
        creation_date = "2022-05-05"
        classification = "TLP:CLEAR"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/mal_lnx_implant_may22.yar"
        
    strings:
        $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
        $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
        $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
        $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }
        
    condition:
        uint32(0)==0x464c457f
        and filesize > 10KB
        and filesize < 50KB
        and (all of ($op*))
}
        