import "pe"
        
rule sekoiaio_wiper_hermeticwiper_variants {
    meta:
        id = "102ecf15-167e-49e4-932c-6334e3cdcc69"
        version = "1.0"
        description = "Matches HermeticWiper and possible variants"
        source = "Sekoia.io"
        creation_date = "2022-02-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "SeLoadDriverPrivilege" wide
        $ = "\\\\.\\PhysicalDrive" wide
        $ = "::$INDEX_ALLOCATION" wide
        $ = "CrashDumpEnabled" wide
        
    condition:
        2 of them and
        pe.characteristics and
        pe.number_of_signatures == 1 and
        pe.number_of_resources > 2 and
        for 2 i in (0..pe.number_of_resources - 1):
        ( uint32be( pe.resources[i].offset+15 ) == 0x4D5A9000 and
        uint16be( pe.resources[i].offset ) == 0x535A )
}
        