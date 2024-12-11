rule sekoiaio_tool_rubeus_strings {
    meta:
        id = "df1860d0-ec34-4c2d-bd83-5f16b26d075c"
        version = "1.0"
        description = "Detects Rubeus"
        source = "Sekoia.io"
        creation_date = "2024-03-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ".Ndr.RPC_DISPATCH_TABLE32"
        $ = ".Ndr.RPC_PROTSEQ_ENDPOINT32"
        $ = ".Ndr.RPC_SERVER_INTERFACE32"
        $ = ".Ndr.NDR_EXPR_DESC32"
        $ = "$krb5tgs${0}$*{1}${2}${3}*${4}${5}" wide
        $ = "$krb5asrep$23${0}@{1}:{2}" wide
        $ = "Unable to decrypt the EncTicketPart using key:" wide
        $ = "[*] Target service  : {0:x}" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        5 of them
}
        