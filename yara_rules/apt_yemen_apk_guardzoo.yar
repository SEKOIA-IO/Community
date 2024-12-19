rule apt_yemen_apk_guardzoo {
    meta:
        id = "f4004e7c-2904-46ea-a3e6-2bdd3e704fea"
        version = "1.0"
        description = "Detects Dex files containing GuardZoo strings."
        author = "Sekoia.io"
        creation_date = "2024-08-09"
        classification = "TLP:CLEAR"
        hash = "3afad114c68489e2d294720339baf570"
        hash = "c59d0f5c8d00485199f147b96c5abca0"
        hash = "75c58948725133160085dc1cfdf602ec"
        hash = "d76a39ee85263900f7e6eaacb804f5e2"
        hash = "51356c95dfe1221c0f4ca2475bc787f8"
        hash = "1d0dd8201c051d9c8d2c945c8b31a48c"
        hash = "b7b6be5e8eec44dd13e1df1f3908fcf0"
        hash = "229984f004578a8fa643afb881d81e8c"
        hash = "f3f1ccb3912c49a0a6ea710a0bd856de"
        hash = "a3f8365bfa5f8185e8c7eba8efc63165"
        hash = "7392deaf81ddf50b8a6f2179538f7e81"
        hash = "c40d56e1586f9fa382c688d624d25525"
        hash = "629fb04b91c4db4ea282440e20317dab"
        hash = "bcebc41628196f8bd119f72e1e8eb47c"
        hash = "f1cfdc9e91c3a20563246cf366b94f10"
        hash = "a75ffb11adbace40a7c59128adba43ad"
        
    strings:
        $classes_1 = "GuardZoo.java"
        $classes_2 = "com/animals"
        $path_1 = "&Password="
        $path_2 = "&Coordinates="
        $path_3 = "&Data="
        $path_4 = "&Device="
        $path_5 = "&ISPICTURE="
        $path_6 = "&Phone_Number="
        $path_7 = "&Provider="
        
    condition:
        uint32be(0) == 0x6465780a and filesize < 10MB and
        ((any of ($classes_*)) and (3 of ($path_*)))
}
        