rule apt_cloudatlas_rtf_shellcode_cve_2018_0798 {
    meta:
        id = "6c602c66-df40-4436-800f-e548dacc1e81"
        version = "1.0"
        description = "CloudAtlas Shellcode for CVE_2018_0798 "
        author = "Sekoia.io"
        creation_date = "2022-12-01"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "6060606061616161616161616161616161616161FB0B00004bE8FFFFFFFFC35F83C71B33C966B908010f0d00ddd8d97424f4668137" ascii nocase
        
    condition:
        filesize < 8MB  and
        all of them
}
        