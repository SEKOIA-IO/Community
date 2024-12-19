rule infostealer_win_gomorrah {
    meta:
        id = "df8f06ba-6c93-4ce3-9857-ced93753f917"
        version = "1.0"
        description = "Detect the Gomorrah infostealer based on specific strings"
        author = "Sekoia.io"
        creation_date = "2022-08-25"
        classification = "TLP:CLEAR"
        
    strings:
        $gom01 = "-------------Developed By th3darkly [ https://gomorrah.pw ]-------------" wide
        $gom02 = "-------------Created By Lucifer [ https://t.me/th3darkly ]-------------" wide
        $gom03 = "--- Dev By https://t.me/@th3darkly ---" wide
        $gom04 = "\\Gomorrah\\Gomorrah\\obj\\Debug\\Gomorrah.pdb" wide
        $gom05 = "Gomorrah.Resources.resources" wide
        
        $str01 = "logs.php?hwid=" wide
        $str02 = "gate.php?hwid=" wide
        $str03 = "task.php?hwid=" wide
        $str04 = "ownloadAndRun" wide
        $str05 = "oftware\\\\Microsoft\\\\Windows Messaging Subsystem\\\\Profiles\\\\9375CFF0413111d3B88A00104B2A6676" wide
        $str06 = "FileZilla\\\\recentservers.xml" wide
        $str07 = "http://ip-api.com/json/" wide
        $str08 = "OutkookStealer" ascii
        $str09 = "update_windows10.youknowcaliber" ascii
        
    condition:
        uint16(0)==0x5A4D and
        ((1 of ($gom*) and 1 of ($str*)) or (7 of ($str*)))
}
        