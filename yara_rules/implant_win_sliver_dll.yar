import "pe"
        
rule implant_win_sliver_dll {
    meta:
        id = "41d83011-a08b-4245-b633-79fe6afaa4d2"
        author = "Sekoia.io"
        creation_date = "2021-11-08"
        modification_date = "2021-12-22"
        description = "Detect the Sliver DLL based on export names (standalone and process/memory dumps)"
        version = "1.1"
        classification = "TLP:CLEAR"
        
    strings:
        $a1 = "main.RunSliver"
        $a2 = "main.DllInstall"
        
    condition:
        (   filesize > 8MB and
        filesize < 11MB and
        uint16be(0) == 0x4d5a and
        pe.characteristics & pe.DLL and
        pe.exports("RunSliver") and
        pe.exports("DllInstall") and
        pe.exports("VoidFunc")
        )
        or
        (
            true and ( uint32be(0) == 0x4d444d50 or
            uint32be(0) == 0x00000000
        ) and $a2 in (@a1..@a1+100)
        )
}
        