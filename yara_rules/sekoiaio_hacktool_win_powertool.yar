rule sekoiaio_hacktool_win_powertool {
    meta:
        version = "1.0"
        description = "Detect PowerTool based on strings"
        source = "Sekoia.io"
        creation_date = "2022-09-09"
        id = "ab8355b8-322d-41a4-82f0-43896c96b9bc"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "C:\\dev\\pt64_en\\Release\\PowerTool.pdb" ascii
        $str1 = "Chage language nedd to restart PowerTool" ascii
        $str2 = "(http://twitter.com/ithurricanept && https://www.linkedin.com/in/powertool)" wide
        $str3 = "Infected=Before Fix, whether to back up the drive files will be fixed?" wide
        $str4 = "Infected?-Are you sure to Fix the Infected Driver File?" wide
        $str5 = "shellex\\ContextMenuHandlers\\PowerTool" wide
        $str6 = "[PowerTool] name=%s, size=%d, %d" ascii
        
    condition:
        uint16(0)==0x5A4D and any of them
}
        