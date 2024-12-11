rule sekoiaio_apt_dark_pink_pdb_path {
    meta:
        id = "695586dc-66de-4f9d-814a-2d81261a7357"
        version = "1.0"
        description = "Detects PDB path of some Dark Pink sample"
        source = "Sekoia.io"
        creation_date = "2023-01-16"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "C:\\Users\\hoang\\source\\repos\\Cucky\\Cucky\\obj\\Release\\net46\\Cucky.pdb" wide ascii
        $s2 = "C:\\Users\\build\\source\\repos\\CtealWebCredential\\Release\\CtealWebCredential.pdb" wide ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 5MB and any of them
}
        