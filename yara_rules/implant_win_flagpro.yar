rule implant_win_flagpro {
    meta:
        id = "08dd2de4-b359-424f-af04-7f294d519363"
        version = "1.0"
        description = "Detect the Flagpro malware used by Blacktech"
        author = "Sekoia.io"
        creation_date = "2022-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "<BODY ID=CV20_LoaderDlg BGCOLOR=LIGHTGREY style=\"font-family:MS Shell Dlg;font-size:8\">" ascii
        $ = "<TABLE WIDTH=100% HEIGHT=100%>" ascii
        $ = "<TR WIDTH=100% HEIGHT=45%>" ascii
        $ = "<TD ALIGN=CENTER VALIGN=BOTTOM>" ascii
        $ = "TODO: Place controls here." ascii
        $ = "<TD ALIGN=RIGHT VALIGN=BOTTOM>" ascii
        $ = "<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonHelp\">Help</BUTTON>&nbsp;&nbsp;<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonOK\">OK</BUTTON>&nbsp;<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonCancel\">Cancel</BUTTON>" ascii
        
        $about_loader = /About V[0-9]+\.[0-9]+_Loader.../ wide
        $path = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\include\\" wide
        $regitry = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\" wide
        
    condition:
        uint16(0)==0x5A4D
        and all of them
}
        