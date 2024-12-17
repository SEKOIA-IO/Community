rule sekoiaio_latrodectus_br4_js_dropper {
    meta:
        id = "042a598d-66fa-4994-a793-228355abd5dd"
        version = "1.0"
        description = "Detect the JS script used to drop Latrodectus"
        author = "Sekoia.io"
        creation_date = "2024-06-25"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = " installer.InstallProduct(msiPath);" ascii
        $s2 = "new ActiveXObject(\"WindowsInstaller.Installer\");" ascii
        
    condition:
        all of them
}
        