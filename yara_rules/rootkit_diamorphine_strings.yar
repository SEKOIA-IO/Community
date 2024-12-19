rule rootkit_diamorphine_strings {
    meta:
        id = "5a28be5c-9a57-4204-a7cc-42dfcaa2c2da"
        version = "1.0"
        description = "Detects Diamorphine linux rootkit based on strings"
        author = "Sekoia.io"
        creation_date = "2024-10-21"
        classification = "TLP:CLEAR"
        hash = "622675e83bab630adc0f1c6c46c4d6d1"
        hash = "013b23213975d2646e2435f058afcacf"
        hash = "f068e83721f10ad74bb6f386a4375a91"
        hash = "ba9d6a6bbde602fd414cea09fcbd1aa0"
        hash = "fdd86788e295010c4e61bf6b589f340e"
        hash = "0d396c1763503b35a7f601831bd684de"
        hash = "66b8955188a3bda7ecdcd51cfd360313"
        hash = "1e4fd8c6bf0e381ac395d9bff1f98a31"
        hash = "ce08ce2b8bc1718052f5d0316e3e71b7"
        hash = "94982037875d4fdb17681866afc12ade"
        hash = "4fa2fe9ccde3e6bd4956e2b93ca5fcb6"
        hash = "644c4ce0bbe4f1f1e3aae537a111d5b8"
        hash = "fb7d594621fbb4f9bdb0eb74f6090ecd"
        hash = "9faf1493164e734f533f0ecfb1737a98"
        hash = "33d48b6c66715ab67a059ab940d759ff"
        
    strings:
        $ = "LKM rootkit" ascii fullword
        $ = "m0nad"
        
    condition:
        uint32be(0) == 0x7f454c46 and all of them
}
        