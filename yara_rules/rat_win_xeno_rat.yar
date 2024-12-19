rule rat_win_xeno_rat {
    meta:
        id = "4be1ff07-8180-42a8-9f51-b5e17bf23442"
        version = "1.0"
        description = "Xeno RAT is an open-source RAT, used by Kimsuky in January 2024"
        author = "Sekoia.io"
        creation_date = "2024-02-09"
        classification = "TLP:CLEAR"
        reference = "https://github.com/moom825/xeno-rat/tree/main/xeno%20rat%20client"
        
    strings:
        $ = "Xeno-manager" wide
        $ = "moom825"
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        