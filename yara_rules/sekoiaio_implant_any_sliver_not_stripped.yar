rule sekoiaio_implant_any_sliver_not_stripped {
    meta:
        id = "35543c7c-c39b-4f96-b37c-1d27736e40fc"
        source = "Sekoia.io"
        creation_date = "2021-11-08"
        modification_date = "2021-12-22"
        description = "Rule which detects non stripped Sliver PE/Dlls/ELFs/MAC-O."
        version = "1.1"
        classification = "TLP:CLEAR"
        
    strings:
        $a1 = "github.com/bishopfox/sliver/implant/sliver/"
        
    condition:
        (
        uint16be(0) == 0x4d5a or
        uint32be(0) == 0x7f454c46 or
        uint32be(0) == 0xcffaedfe
        )
        
        and filesize < 11MB
        and filesize > 8MB
        and #a1 > 200
}
        