import "pe"
        
rule latrodectus_exports {
    meta:
        version = "1.0"
        description = "detection based on the exports"
        creation_date = "2024-07-03"
        classification = "TLP:CLEAR"
        author = "Sekoia.io"
        id = "29076cf5-f391-42f2-918f-e1c929bd368d"
        
    condition:
        (pe.exports("stow") or pe.exports("homq") or pe.exports("scub")) and 
        pe.number_of_exports >= 3 and uint16(0) == 0x5a4d
}
        