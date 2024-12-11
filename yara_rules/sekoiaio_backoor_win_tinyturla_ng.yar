import "pe"
        
rule sekoiaio_backoor_win_tinyturla_ng {
    meta:
        id = "019043bb-0212-4b73-bc93-03e9a746d28d"
        version = "1.0"
        description = "Detect the TinyTurla-NG backdoor used by Turla"
        source = "Sekoia.io"
        creation_date = "2024-03-04"
        classification = "TLP:CLEAR"
        reference = "https://blog.talosintelligence.com/tinyturla-next-generation/"
        hash1 = "267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b"
        hash2 = "d6ac21a409f35a80ba9ccfe58ae1ae32883e44ecc724e4ae8289e7465ab2cf40"
        
    strings:
        $ = "delkill /F /IM explENT_USER\\Softwar"
        $ = "Set-PSReadLineOption -HistorySaveStyle SaveNothing"
        $ = "changeshell"
        $ = "chcp 437 > $null"
        $ = "powershell.exe -nologo"
        
    condition:
        // Strings
        uint16be(0) == 0x4d5a and all of them
        
        // Imphash
        or pe.imphash() == "2240ae6f0dcbc0537836dfd9205a1f2b"
}
        