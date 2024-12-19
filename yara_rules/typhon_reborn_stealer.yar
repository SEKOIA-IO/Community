import "pe"
        
rule typhon_reborn_stealer {
    meta:
        id = "aab7279b-b651-4092-b988-d186d0a433de"
        version = "1.0"
        description = "Typhon Reborn v2 string based detection"
        author = "Sekoia.io"
        creation_date = "2023-05-15"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "api.telegram.org/bot" wide
        $s2 = "TyphonReborn Stealer v2 log!" wide
        
    condition:
        all of them and pe.is_pe
}
        