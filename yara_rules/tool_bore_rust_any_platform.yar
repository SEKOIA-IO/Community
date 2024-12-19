rule tool_bore_rust_any_platform {
    meta:
        id = "c0ec0d72-de8e-4b96-9db6-a7a4e2f693f1"
        version = "1.0"
        description = "Detects bore tunneling tool"
        author = "Sekoia.io"
        creation_date = "2023-07-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "bore_cli::" ascii
        $ = "server handshake failed" ascii
        $ = "server listening" ascii
        $ = "connected to server" ascii
        $ = "server requires authentication, but no client secret was provided" ascii
        $ = "client port number too low" ascii
        $ = "forwarding connection" ascii
        $ = "Address of the remote server to expose local ports" ascii
        
    condition:
        (uint32be(0) == 0x7f454c46 or
         uint32be(0) == 0xfeedface or
         uint32be(0) == 0xfeedfacf or
         uint32be(0) == 0xcafebabe or
         uint16be(0) == 0x4d5a) and
        filesize < 15MB and
        5 of them
}
        