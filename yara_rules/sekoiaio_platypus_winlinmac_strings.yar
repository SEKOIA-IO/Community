rule sekoiaio_platypus_winlinmac_strings {
    meta:
        id = "4519448d-b91b-4794-9521-359b8cf4af78"
        version = "1.0"
        description = "Catch Platypus based on strings"
        source = "Sekoia.io"
        creation_date = "2023-12-07"
        classification = "TLP:CLEAR"
        
    strings:
        $pl1 = "platypus.go" ascii
        $pl2 = "Platypus/lib/context/server.go" ascii
        $pl3 = "Platypus/lib/context/context.go" ascii
        $pl4 = "Platypus/lib/context/client.go" ascii
        $pl5 = "github.com/WangYihang/" ascii
        $f1 = "reflection/reflection.go" ascii
        $f2 = "socksUsernamePassword" ascii
        $go = "/golang" ascii
        
    condition:
        uint32(0)==0x464c457f and 4 of ($pl*) and 1 of ($f*) and #go > 30
}
        