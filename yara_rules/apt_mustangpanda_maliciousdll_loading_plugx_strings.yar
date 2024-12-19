import "pe"
        
rule apt_mustangpanda_maliciousdll_loading_plugx_strings {
    meta:
        id = "2296ac6e-63f5-4cff-aeb7-2c5205e6f559"
        version = "1.0"
        description = "Detects MustangPanda malicious DLL"
        author = "Sekoia.io"
        creation_date = "2023-12-18"
        classification = "TLP:CLEAR"
        hash = "651c096cf7043a01d939dff9ba58e4d69f15b2244c71b43bedb4ada8c37e8859"
        
    strings:
        $ = "VirtualAlloc"
        $ = "VirtualFree"
        $ = "VirtualProtect"
        $ = "VirtualQuery"
        $ = "GCC: (MinGW-W64"
        
    condition:
        pe.exports("MsiProvideQualifiedComponentW") 
        and all of them
}
        