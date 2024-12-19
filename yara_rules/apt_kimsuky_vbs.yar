rule apt_kimsuky_vbs {
    meta:
        id = "3f92dbda-2ddb-4fa3-a587-743f65ced9e4"
        version = "1.0"
        description = "VBS files used by Kimsuky"
        author = "Sekoia.io"
        creation_date = "2024-09-23"
        classification = "TLP:CLEAR"
        hash = "12386be22ca82fce98a83a5a19e632bc"
        hash = "7b5783d42240651af78ebf7e01b31fe8"
        hash = "ff7d68e5fb253664ce64c85457b28041"
        hash = "622358469e5e24114dd0eb03da815576"
        hash = "edbb2aa40408e2a7936067ace38b445b"
        hash = "73ed9b012785dc3b3ee33aa52700cfe4"
        
    strings:
        $ = ")):Next:Execute " ascii
        $ = "=\"\":" ascii
        $ = "\":for "
        
    condition:
        all of them and filesize < 10KB
}
        