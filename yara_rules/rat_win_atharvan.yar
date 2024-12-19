rule rat_win_atharvan {
    meta:
        id = "61347490-d281-4892-adba-89cf6187545f"
        version = "1.0"
        description = "Detect Atharvan RAT"
        author = "Sekoia.io"
        creation_date = "2023-02-23"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = {44 3a 5c 72 61 6e 67 5c 54 4f 4f 4c 5c 33 52 41 54}
        
    condition:
        all of them
}
        