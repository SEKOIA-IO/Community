rule apt_nobelium_hta_reg_dropper {
    meta:
        id = "9f6a2154-c33a-4c38-9667-7479bf49c310"
        description = "Matches HTA dropper file used by NOBELIUM and ISO files containing it"
        hash = "054940ba8908b9e11f57ee081d1140cb"
        hash = "b7ca8c46dc1bfc1d9cb9ce04a4928153"
        version = "1.0"
        creation_date = "2021-12-07"
        modification_date = "2021-12-07"
        classification = "TLP:WHITE"
        source="SEKOIA"
    strings:
        $w = "RegWrite(" nocase
        $x = { 2b 3d 20 64 6f 63 75 6d 
               65 6e 74 2e 67 65 74 45 
               6c 65 6d 65 6e 74 42 79 
               49 64 28 22 [0-4] 22 29 
               2e 69 6e 6e 65 72 48 54 
               4d 4c }
        $y = "<body onload=" nocase
        $z = "hidden" nocase
    condition:
        $y and 
        (3 < #z) and 
        (3 < #x) and 
        (1 < #w)
}
