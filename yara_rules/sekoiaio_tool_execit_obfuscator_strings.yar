rule sekoiaio_tool_execit_obfuscator_strings {
    meta:
        id = "59eaeb20-150b-41a4-b866-1c91a07623ac"
        version = "1.0"
        description = "Detects ExecIT Dlls"
        author = "Sekoia.io"
        creation_date = "2024-09-11"
        classification = "TLP:CLEAR"
        hash = "1c185e2e11d8eadccfb130766ca30d85"
        hash = "a0898f57f2b139ea278d8a7e97bbe358"
        hash = "e0e12a8891f5585ce1ad55dbffb4f9c2"
        hash = "d4102676d536bacffcf6c94364e26828"
        
    strings:
        $ = "yromeMlautriVetacollAtN"
        $ = "xEdaerhTetaerCtN"
        $ = "tcejbOelgniSroFtiaWtN"
        $ = "lld.esablenrek"
        $ = "txetnoCdaerhTteG"
        $ = "txetnoCdaerhTteS"
        $ = "cef_api_hash"
        $ = "cef_execute_process"
        $ = "cef_get_path"
        
    condition:
        uint16be(0) == 0x4d5a and
        5 of them
}
        