rule sekoiaio_tool_safetykatz {
    meta:
        id = "90f93244-38a7-4574-87c6-15d494e9173b"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2023-06-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "SafetyKatz" ascii fullword
        $s2 = "get_mimikatz" ascii fullword
        $s3 = "$8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii fullword
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and 
        all of them
}
        