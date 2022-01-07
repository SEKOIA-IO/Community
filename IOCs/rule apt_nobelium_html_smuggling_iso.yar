rule apt_nobelium_html_smuggling_iso {
    meta:
        id = "9bd5b626-8ea3-4607-a858-58deff18396c"
        version = "1.0"
        description = "Detect HTML smuggling with ISO"
        hash = "b87073c34a910f20a83c04c8efbd4f43"
        hash = "3d18bc4bfe1ec7b6b73a3fb39d490b64"
        source = "SEKOIA"
        creation_date = "2022-01-02"
        modification_date = "2022-01-02"
        classification = "TLP:WHITE"
    strings:
		$ = "new Blob"
		$ = ".click();"
		$ = { 28 [1-20] 2c 22 [1-20] 
                 2e 69 73 6f 22 2c 22 61 
                 70 70 6c 69 63 61 74 69
                 6f 6e 2f 78 2d 63 64 2d
                 69 6d 61 67 65 22 29 }
    condition:
        filesize > 1MB and filesize < 2MB and all of them
}
