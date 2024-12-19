rule infostealer_win_vidar_strings_nov23 {
    meta:
        version = "1.0"
        description = "Finds Vidar samples based on the specific strings"
        author = "Sekoia.io"
        reference = "https://twitter.com/crep1x/status/1722652451319202242"
        creation_date = "2023-11-10"
        id = "b2c17627-f9b8-4401-b657-1cce560edc76"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "MachineID:" ascii
        $str02 = "Work Dir: In memory" ascii
        $str03 = "[Hardware]" ascii
        $str04 = "VideoCard:" ascii
        $str05 = "[Processes]" ascii
        $str06 = "[Software]" ascii
        $str07 = "information.txt" ascii
        $str08 = "%s\\*" ascii
        $str09 = "Select * From AntiVirusProduct" ascii
        $str10 = "SELECT target_path, tab_url from downloads" ascii
        $str11 = "Software\\Martin Prikryl\\WinSCP 2\\Configuration" ascii
        $str12 = "UseMasterPassword" ascii
        $str13 = "Soft: WinSCP" ascii
        $str14 = "<Pass encoding=\"base64\">" ascii
        $str15 = "Soft: FileZilla" ascii
        $str16 = "passwords.txt" ascii
        $str17 = "build_id" ascii
        $str18 = "file_data" ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of ($str*)
}
        