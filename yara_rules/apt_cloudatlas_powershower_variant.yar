rule apt_cloudatlas_powershower_variant {
    meta:
        id = "416d0cb0-bc59-47ae-8a98-d7b39f8108ab"
        version = "1.0"
        description = "Detects PowerShower"
        author = "Sekoia.io"
        creation_date = "2023-12-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "[System.Text.Encoding]::" ascii wide
        $s2 = "{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}"  ascii wide
        
    condition:
        filesize < 10KB and
        all of them
}
        