rule sekoiaio_trojan_android_brata {
    meta:
        id = "fde9b82e-c677-44ed-b512-b225a3aba201"
        author = "Sekoia.io"
        creation_date = "2022-01-27"
        description = "Detect samples of the Android banking trojan BRATA"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $goo0 = "Google Play services error"
        $goo1 = "Error de Serveis de Google Play"
        $goo2 = "Fehler bei Zugriff auf Google Play-Dienste"
        $goo3 = "Erro nos servizos de Google Play"
        $goo4 = "Fout met Google Play-services"
        $goo5 = "Virhe Google Play -palveluissa"
        $goo6 = "Erro do Google Play Services"
        $goo7 = "Error de Google Play Services"
        
        $res0 = "res/xml/device_admin.xml"
        $res1 = "res/xml/windowchangedetectingservice.xml"
        $res2 = "res/xml-v22/windowchangedetectingservice.xml"
        
    condition:
        uint32be(0) == 0x504B0304
        and filesize > 2MB
        and filesize < 6MB
        and 7 of ($goo*) and 2 of ($res*)
}
        