rule tool_efspotato {
    meta:
        id = "4440ea37-d7d0-4107-867c-576c6e2f4f7e"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "usage: EfsPotato <cmd> [pipe]" ascii wide
        $s2 = "Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability)." ascii wide
        $s3 = "Part of GMH's fuck Tools, Code By zcgonvh." ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 4MB and all of them
}
        