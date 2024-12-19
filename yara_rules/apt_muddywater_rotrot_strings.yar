rule apt_muddywater_rotrot_strings {
    meta:
        id = "f7bc195a-0e60-4495-b78a-78f101543700"
        version = "1.0"
        description = "Detects RotRot backdoor based on strings"
        author = "Sekoia.io"
        creation_date = "2024-06-10"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "qsphsbnebub"
        $s2 = "rtqitcofcvc"
        $s3 = "surjudpgdwd"
        $s4 = "tvskveqhexe"
        $s5 = "uwtlwfrifyf"
        $s6 = "vxumxgsjgzg"
        
        $t1 = "MpbeMjcsbs"
        $t2 = "NqcfNkdtct"
        $t3 = "OrdgOleudu"
        $t4 = "PsehPmfvev"
        $t5 = "QtfiQngwfw"
        $t6 = "RugjRohxgx"
        
        $u1 = "UfsnjobufKpcPckfdu"
        $u2 = "VgtokpcvgLqdQdlgev"
        $u3 = "WhuplqdwhMreRemhfw"
        $u4 = "XivqmrexiNsfSfnigx"
        $u5 = "YjwrnsfyjOtgTgojhy"
        $u6 = "ZkxsotgzkPuhUhpkiz"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 100KB and filesize < 300KB and
        any of ($s*) and any of ($t*) and any of ($u*)
}
        