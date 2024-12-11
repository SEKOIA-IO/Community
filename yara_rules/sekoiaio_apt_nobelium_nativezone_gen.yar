import "pe"
        
rule sekoiaio_apt_nobelium_nativezone_gen {
    meta:
        id = "e16cac97-38dd-4145-95f5-cf641940a19b"
        version = "1.0"
        description = "Detects NativeZone used in 2022"
        source = "Sekoia.io"
        creation_date = "2022-02-25"
        classification = "TLP:CLEAR"
        
    strings:
        $rich = { 52 69 63 68 [4] 00 }
        $obs = { C7 85 [8] C7 85 }
        $nobs = { C7 85 [6] 00 00 C7 85 }
        
    condition:
        pe.DLL and
        filesize < 2500KB and
        pe.number_of_exports > 20 and
        pe.number_of_imports < 30 and
        (
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "VirtualProtect")
        ) and for any i in (0..pe.number_of_sections - 1):
        ( pe.sections[i].name == ".rdata" and
        pe.sections[i].raw_data_size > 300000 )
        and #obs > 300
        and #nobs < 150
        and not $rich
}
        