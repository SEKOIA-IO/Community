rule sekoiaio_koiloader_lnk {
    meta:
        id = "e82975b9-94b7-4de8-8cd5-d594aa80cf02"
        version = "1.0"
        description = "LNK file leading to deploy KoiLoader"
        author = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "bat & schtasks /create" wide
        $s2 = "/sc minute /mo 1" wide
        $s3 = "c3RhcnQgL21pbiBwb3dlcnNoZWxsIC1jb21tYW5kICJJV1IgLVVzZUJhc2ljUGFyc2luZyAnaHR0cHM6" wide
        $s4 = " & certutil -f -decode " wide
        
    condition:
        uint32(0) == 0x0000004c and all of them
}
        