rule apt_oilrig_powerexchange {
    meta:
        id = "cb6b370f-7b05-480b-865e-ac81ded4a2a4"
        version = "1.0"
        description = "Detects OilRig's PowerExchange backdoor"
        author = "Sekoia.io"
        creation_date = "2023-10-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "($h.value).PadRight((($h.value).Length+($h.value).Length%4),'='" ascii wide
        $ = "(($h.value).Length%4 -ne 0)" ascii wide
        $ = "-match \"@@(.*)@@\"" ascii wide
        $ = "[Environment]::NewLine+$_.Exception.Message | Out-File -FilePath" ascii wide
        $ = "ContainsSubjectStrings.Add(\"@@\")" ascii wide
        
    condition:
        2 of them and filesize < 50KB
}
        