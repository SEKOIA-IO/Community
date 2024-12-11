rule sekoiaio_rat_win_tutclient {
    meta:
        id = "2bd2d61f-3654-4acd-9773-8d3617c67ee0"
        version = "1.0"
        description = "Detect the open-source RAT TutClient"
        source = "Sekoia.io"
        creation_date = "2024-02-09"
        classification = "TLP:CLEAR"
        reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
        
    strings:
        $ = "Clipboard Data Not Retrived!" wide
        $ = "Remote Cmd stream reading failed!" wide
        $ = "PasswordFox" wide
        $ = "[Right Click, Position: x = <rtd.xpos>; y = <rtd.ypos>]" wide
        $ = "SendCommand"
        $ = "HandleCommand"
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        