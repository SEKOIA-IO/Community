rule sekoiaio_apt_kimsuky_sharptongue_vbslauncher_strings {
    meta:
        id = "82bd648c-2961-4945-950e-8fb1e4650338"
        version = "1.0"
        description = "Detects VBS Launchers used by SharpTongue"
        author = "Sekoia.io"
        creation_date = "2022-07-29"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "powershell" ascii wide
        $ = "On Error Resume Next" ascii wide
        $ = "oShell.run(tmp0,0" ascii wide
        
    condition:
        all of them and filesize < 10KB
}
        