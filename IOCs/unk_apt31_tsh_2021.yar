rule unk_apt31_tsh_2021 {
    meta:
        description = "Detect APT31-linked TSH sample. This rule is quite specific with the $s3 string. We would advise removing this string to cover other TSH samples."
        version = "1.0"
        creation_date = "2021-10-11"
        modification_date = "2021-10-11"
        classification = "TLP:WHITE"
        hash = "4640805c362b1e5bee5312514dd0ab2b"
        source="SEKOIA.IO"
        version="1.0"
    strings:
        $s1 = { C6 00 48 C6 40 05 49 C6
        40 01 49 C6 40 06 4C C6
        40 02 53 C6 40 07 45 C6
        40 03 54 C6 40 08 3D C6
        40 04 46 C6 40 09 00 }

        $s2 = { C6 00 54 C6 40 03 4D C6
        40 01 45 C6 40 04 3D }

        $s3 = "www.moperfectstore.com"
    condition:
        int32be(0) == 0x7f454c46 and
        filesize < 1MB and filesize > 900KB and
        all of them
}
rule apt_misp_apt31_orb_2021 {   
    meta:
        description = "Detects APT31 ORB implant"
        version = "1.0"
        creation_date = "2021-10-11"
        modification_date = "2021-10-11"
        classification = "TLP:WHITE"
        hash = "77c73b8b1846652307862dd66ec09ebf"
	  source="SEKOIA.IO"
        version="1.0"
    strings:
        $s1 = "mv -f %s %s ;chmod 777 %s"
        $s2 = "GET /plain HTTP/1.1"
        $s3 = "exc_cmd time out"
        $s4 = "exc_cmd pipe err"
        $s5 = { 2e 2f [1-10] 20 20 64 65 6c }

    condition:
        int32be(0) == 0x7f454c46 and 
        filesize < 800KB and          filesize > 400KB and 
        4 of ($s*)
}