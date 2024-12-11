import "pe"
        
rule sekoiaio_tool_pchunter_and_related_certificate {
    meta:
        id = "757c7738-4ee8-4b4e-bdda-0c5b0c010f40"
        version = "1.0"
        description = "Detects PCHunter and associated binairies & drivers"
        source = "Sekoia.io"
        creation_date = "2022-09-07"
        classification = "TLP:CLEAR"
        
    condition:
        uint16be(0) == 0x4d5a and
        for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].serial contains "05:51:bc:8c:6a:a2:ca:03:2b:c6:71:38:30:d8:49:a3"
      ) and filesize>400KB and filesize<20MB
}
        