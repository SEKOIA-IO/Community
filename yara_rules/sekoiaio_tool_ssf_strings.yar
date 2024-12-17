rule sekoiaio_tool_ssf_strings {
    meta:
        id = "47fc3df8-a153-4045-a5f0-ed30df662984"
        version = "1.0"
        description = "Detects SSF based on strings"
        author = "Sekoia.io"
        creation_date = "2024-05-31"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "could NOT read SSF reply"
        $ = "SSF reply NOT ok {}"
        $ = "SSF reply OK"
        $ = "SSF protocol error {}"
        $ = "SSF reply ok"
        $ = "SSF version NOT read {}"
        $ = "SSF version {}"
        $ = "SSF version NOT supported {}"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        4 of them
}
        