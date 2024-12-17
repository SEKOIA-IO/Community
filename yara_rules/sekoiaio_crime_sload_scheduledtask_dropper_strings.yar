rule sekoiaio_crime_sload_scheduledtask_dropper_strings {
    meta:
        id = "01c51da8-71a5-449f-a609-933c37bc2e63"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2022-08-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$hh='hi'+'dd'+'en';"
        $ = { 7D 65 6C 73 65 7B 0A 24 72 73 3D 30 3B 0A 7D 0A }
        $ = { 6B 69 6C 6C 20 2D 6E 61 6D 65 20 2A 77 65 72 73 68 65 6C 2A }
        
    condition:
        all of them
}
        