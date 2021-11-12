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