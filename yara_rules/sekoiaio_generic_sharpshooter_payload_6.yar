rule sekoiaio_generic_sharpshooter_payload_6 {
    meta:
        id = "53506a3e-b0d8-4a1e-88d9-485e829f25cb"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        source = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "function ${rc4Function}(r,o){for("
        $ = "function ${b64AndRC4Function}(r,o){var"
        $ = "Real-Time Scanning: No threats detected"
        $ = "Please wait while your file is being downloaded..."
        
    condition:
        3 of them and filesize < 2MB
}
        