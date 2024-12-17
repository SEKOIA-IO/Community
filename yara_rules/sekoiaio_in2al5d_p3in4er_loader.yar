import "pe"
        
rule sekoiaio_in2al5d_p3in4er_loader {
    meta:
        id = "6dd3046d-55fb-4bcc-8735-dbc0add4d570"
        version = "1.0"
        description = "Invalid printer loader detection based on the XOR key"
        author = "Sekoia.io"
        creation_date = "2023-04-24"
        classification = "TLP:CLEAR"
        
    strings:
        $xor_key = "in2al5d p3in4er" ascii fullword
        
    condition:
        all of them and (filesize > 4MB and filesize < 7MB) and pe.is_pe
}
        