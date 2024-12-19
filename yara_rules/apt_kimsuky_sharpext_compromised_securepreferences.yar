rule apt_kimsuky_sharpext_compromised_securepreferences {
    meta:
        id = "aeda5d15-82e1-4ffc-8252-1eb4fc78d024"
        version = "1.0"
        description = "Detects compromised Chrome SecurePreferences file"
        author = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "\"devtools\", \"tabs\", \"webNavigation\", \"webRequest\", \"webRequestBlocking\""
        $ = "AppData\\\\Roaming"
        $ = "https://*/*"
        
    condition:
        all of them
}
        