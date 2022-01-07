rule apt_nobelium_b64_to_Uint8Array {
    meta:
        id = "66c9b00b-f021-4115-b9ec-d1e1f491ce72"
        description = "Detect Base64 decode to Uint8Array used in NOBELIUM HTML files"
        hash = "3d18bc4bfe1ec7b6b73a3fb39d490b64"
        version = "1.0"
        creation_date = "2021-12-02"
        modification_date = "2021-12-02"
        classification = "TLP:WHITE"
        source="SEKOIA"
    strings:
        $a1 = "atob("
        $l0 = { 20 3c 20 [2-10] 2e 6c 65 6e 67 74 68 3b 20 69 2b 2b 29 7b }
        $l1 = { 5b 69 5d 20 3d 20 [2-10] 2e 63 68 61 72 43 6f 64 65 41 74 28 69 29 3b }
        $a2 = "new Uint8Array" 
    condition:
        $l0 in (@a1..@a2) and 
        $l1 in (@a1..@a2) and 
        filesize > 1MB and filesize < 3MB 
}
