rule apt_apt10_hui_loader {
    meta:
        id = "97d17052-80d0-4f8e-8b3a-2e0d622522a9"
        version = "1.0"
        description = "Specific string for HUI Loader"
        author = "Sekoia.io"
        creation_date = "2022-07-04"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "HUIHWASDIHWEIUDHDSFSFEFWEFEWFDSGEFERWGWEEFWFWEWD" wide fullword
        
    condition:
        (uint16be(0) == 0x4d5a) 
        and filesize > 30KB and filesize < 100KB
        and 1 of them
}
        