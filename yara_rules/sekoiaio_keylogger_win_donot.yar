rule sekoiaio_keylogger_win_donot {
    meta:
        id = "4f67dda7-da68-4496-a8b4-a8a769ddd763"
        version = "1.0"
        description = "Detect the DoNot's keylogger malware"
        author = "Sekoia.io"
        creation_date = "2023-03-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "iwrct2mTFAu0ew1nyqQgoaNtNo0+52R0XiTKbwy1W48Bn1b2YcNt0+tptyY6oGoAeLDGekM/yHcdikNGi8bLqkUQ8CIdkWeT3QiympOTfjs="
        $ = "ZmVwZW9kbWZ2c24ucHMuZ3h4LngweXBvdWpkYm1qcXE7YnFmVXp1LmZvb3VEcA=="
        
    condition:
       1 of them
}
        