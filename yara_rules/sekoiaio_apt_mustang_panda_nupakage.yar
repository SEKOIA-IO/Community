rule sekoiaio_apt_mustang_panda_nupakage {
    meta:
        id = "bd62c220-addc-48e9-bd01-2eff687ac3ce"
        version = "1.0"
        description = "Detects NUPAKAGE malware (only PDB, too much false positives)"
        source = "Sekoia.io"
        creation_date = "2023-03-24"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "D:\\Project\\NEW_PACKAGE_FILE\\Release\\NEW_PACKAGE_FILE.pdb" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and all of them
}
        