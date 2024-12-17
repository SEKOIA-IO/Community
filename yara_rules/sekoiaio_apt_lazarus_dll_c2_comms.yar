rule sekoiaio_apt_lazarus_dll_c2_comms {
    meta:
        id = "9b379aa8-77ce-4c76-ab13-05e35ebfbdfe"
        version = "1.0"
        description = "Detects DLL communicating with the C2"
        author = "Sekoia.io"
        creation_date = "2023-04-04"
        classification = "TLP:CLEAR"
        hash1 = "fe948451df90df80c8028b969bf89ecbf501401e7879805667c134080976ce2e"
        hash2 = "bb1066c1ca53139dc5a2c1743339f4e6360d6fe4f2f3261d24fc28a12f3e2ab9"
        hash3 = "dca33d6dacac0859ec2f3104485720fe2451e21eb06e676f4860ecc73a41e6f9"
        hash4 = "69dd140f45c3fa3aaa64c69f860cd3c74379dec37c46319d7805a29b637d4dbf"
        
    strings:
        $x1 = "vG2eZ1KOeGd2n5fr" ascii fullword
        $s1 = "Windows %d(%d)-%s" ascii fullword
        $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" wide fullword
        
        $op1 = {B8 C8 00 00 00 83 FB 01 44 0F 47 E8 41 8B C5 48 8B B4 24 E0 18 00 00 4C 8B A4 24 E8 18 00 00 48 8B 8D A0 17 00 00 48 33 CC}
        $op2 = {33 D2 46 8D 04 B5 00 00 00 00 66 0F 1F 44 00 00 49 63 C0 41 FF C0 8B 4C 84 70 31 4C 94 40 48 FF C2}
        $op3 = {89 5C 24 50 0F 57 C0 C7 44 24 4C 04 00 00 00 C7 44 24 48 40 00 00 00 0F 11 44 24 60 0F 11 44 24 70 0F 11 45 80 0F 11 45 90}
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and (
        filesize < 500KB and(
            1 of ($x*)
            or 2 of them
        )
        or (
            $x1 and 1 of ($s*)
            or 3 of them
        ))
}
        