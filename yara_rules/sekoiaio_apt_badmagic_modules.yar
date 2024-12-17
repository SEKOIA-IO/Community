import "pe"
        
rule sekoiaio_apt_badmagic_modules {
    meta:
        id = "e4f1f706-4a46-4a09-b598-e4e8d80f2c4b"
        version = "1.0"
        description = "Detect the modules used by the CloudWizard framework"
        author = "Sekoia.io"
        creation_date = "2023-05-25"
        classification = "TLP:CLEAR"
        hash = "no hash has been found on 2023-05-25 to test the rule"
        
    condition:
        pe.DLL and
        pe.exports("Start") and
        pe.exports("Stop") and
        pe.exports("Whoami") and
        pe.exports("GetResult") and
        pe.exports("GetSettings")
}
        