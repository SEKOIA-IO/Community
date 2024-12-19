rule hacktool_gtunnel_strings {
    meta:
        id = "f20a4400-8ae6-4954-b643-0a8847f037f0"
        version = "1.0"
        description = "Detects Go gTunnel based on strings"
        author = "Sekoia.io"
        creation_date = "2023-04-24"
        classification = "TLP:CLEAR"
        
    strings:
        $repo = "github.com/hotnops/gTunnel/" ascii fullword
        $s1 = "common.(*Tunnel).GetControlStream"
        $s2 = "common.(*Tunnel).handleIngressCtrlMessages"
        $s3 = "client..inittask"
        $s4 = "client.file_client_proto_rawDescGZIP."
        $s5 = "common.(*SocksServer).Start."
        $s6 = "client.(*TunnelControlMessage).GetConnectionId"
        $s7 = "protobuf/reflect/protoreflect.ProtoMessage"
        
    condition:
        (uint32be(0) == 0x7f454c46 or 
         uint16be(0) == 0x4d5a or 
         uint32be(0) == 0xfeedface or 
         uint32be(0) == 0xfeedfacf or 
         uint32be(0) == 0xcafebabe ) and
         #repo > 200 or 5 of ($s*)
}
        