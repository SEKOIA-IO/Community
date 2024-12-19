rule tool_win_gosecretsdump {
    meta:
        id = "9225fe95-e37c-48ff-b5b5-680f255349bd"
        version = "1.0"
        description = "Finds gosecretsdump EXE based on strings"
        author = "Sekoia.io"
        reference = "https://github.com/C-Sto/gosecretsdump/releases"
        creation_date = "2024-06-10"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "github.com/C-Sto/gosecretsdump" ascii
        $str02 = "/pkg/esent" ascii
        $str03 = "/pkg/ditreader" ascii
        $str04 = "/pkg/samreader" ascii
        $str05 = "ntdsFileLocation" ascii
        $str06 = "NTDSLoc" ascii
        $str07 = "SAMEntries" ascii
        $str08 = "SAMHashAES" ascii
        $str09 = "NTLMHash" ascii
        $str10 = "HasNoLMHashPolicy" ascii
        $str11 = "PreviousIncBackup" ascii
        $str12 = "Esent_record" ascii
        
    condition:
        uint16(0)==0x5A4D and 7 of them
}
        