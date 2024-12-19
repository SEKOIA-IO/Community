import "pe"
        
rule apt_muddywater_moriagent {
    meta:
        id = "e7a83663-6a30-416a-8f29-87a6b9445ea4"
        version = "1.0"
        description = "Detects Muddy's Mori Agent implant"
        author = "Sekoia.io"
        creation_date = "2022-01-14"
        classification = "TLP:CLEAR"
        
    strings:
        $mut = "0x50504060" ascii fullword
        $cmd1 = "TType" ascii fullword
        $cmd2 = "TPath" ascii fullword
        $cmd3 = "TFileid" ascii fullword
        $cmd4 = "TCommand" ascii fullword
        $cmd5 = "TTimeout" ascii fullword
        $cmd6 = "TFilter" ascii fullword
        
    condition:
        
        uint16be(0) == 0x4d5a and
        ( ( pe.number_of_exports == 2 and
        pe.exports("DllRegisterServer") and
        pe.exports("DllUnregisterServer") ) and
        ( 5 of them ) )
}
        