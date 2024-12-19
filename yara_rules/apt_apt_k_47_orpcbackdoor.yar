rule apt_apt_k_47_orpcbackdoor {
    meta:
        id = "9768371d-763f-45df-b727-ccda97501aaa"
        version = "1.0"
        description = "Detects ORPCBackdoor used by APT-K-47"
        author = "Sekoia.io"
        creation_date = "2024-02-14"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "RegisteredOrganization:\t\t\t" ascii wide
        $s2 = "To Be Filled By O.E.M" ascii wide
        $s3 = ">> "
        $s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%u" wide
        $s5 = "Error! GetSystemDirectory failed."
        $s6 = "Domain:\t\t\t\t"
        
    condition:
        all of them and filesize < 300KB and uint16be(0) == 0x4d5a
}
        