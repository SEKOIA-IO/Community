rule tool_sharpsecdump {
    meta:
        id = "359bf48b-81c8-4d12-ac02-777d4865411a"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-06-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "SharpSecDump"
        $s2 = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7"
        $s3 = "Md4Hash2"
        $s4 = "RidToKey"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and
        all of them
}
        