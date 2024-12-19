import "pe"
        
rule apt_menupass_maliciouslibvlc_dll {
    meta:
        id = "8b6b56f3-33b5-41cf-8bcb-e653c98718bd"
        version = "1.0"
        description = "Detects the malicious LibVLC variants used by MenuPass"
        author = "Sekoia.io"
        creation_date = "2022-04-06"
        classification = "TLP:CLEAR"
        
    condition:
        pe.DLL and
        pe.number_of_exports < 15 and
        for all i in (0..pe.number_of_exports - 1):
        (pe.export_details[i].name contains "libvlc_")
}
        