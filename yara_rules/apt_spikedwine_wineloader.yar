import "pe"
        
rule apt_spikedwine_wineloader {
    meta:
        id = "7a599076-cd9d-42c4-a83a-9a991ede19fb"
        version = "1.0"
        description = "Detects vineloader"
        author = "Sekoia.io"
        creation_date = "2024-02-29"
        classification = "TLP:CLEAR"
        
    strings:
        $c = { E8 ?? ?? ?? ?? 48 8D 0D
        ?? ?? ?? ?? 48 8D 05 ??
        ?? ?? ?? 48 89 05 ?? ??
        ?? ?? 48 C7 05 ?? ?? ??
        ?? ?? ?? 00 00 48 C7 05
        ?? ?? ?? ?? ?? ?? 00 00 }
        
    condition:
        pe.is_dll() and
        filesize < 100KB and
        for any export in pe.export_details: (
            $c in (export.offset..export.offset+100)
        )
}
        