rule backdoor_mul_supershell_client {
    meta:
        id = "3498ca9e-a165-4dda-bc15-2e5d6d43d9c1"
        version = "1.0"
        description = "Detect the Supershell client (unpacked) by looking for github references"
        author = "Sekoia.io"
        creation_date = "2024-04-25"
        classification = "TLP:CLEAR"
        hash1 = "a42906f8b392089fa1fe3ea264f6cb549ce5437b5ea253d9e1b8dd94bf115dad"
        hash2 = "d97b41e8cd6b63cd55c9a4f99ccadf5a9141088319bc9eb467d96e54080f3c85"
        hash3 = "2b54d1c064892a22f48b5742ba6da55bf62b73e5b1e0649e8b7880b286498735"
        hash4 = "0dedab2ef8d44f9beef782a29dd8f628dd0218b90f23f729b315660437019ccd"
        hash5 = "2484de7944889d784b8229f4fd756d3930e55c91654921019db4437877e30ab7"
        
    strings:
        $ = "github.com/NHAS/reverse_ssh/internal/client/"
        $ = "golang.org"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and all of them
}
        