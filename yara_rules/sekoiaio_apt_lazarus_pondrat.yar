rule sekoiaio_apt_lazarus_pondrat {
    meta:
        id = "a957c158-a79a-4d7a-8473-b6960cf02d9b"
        version = "1.0"
        description = "Detects PondRAT via mangled command names"
        author = "Sekoia.io"
        creation_date = "2024-09-23"
        classification = "TLP:CLEAR"
        hash = "b62c912de846e743effdf7e5654a7605"
        hash = "61d7b2c7814971e5323ec67b3a3d7f45"
        hash = "ce35c935dcc9d55b2c79945bac77dc8e"
        hash = "f50c83a4147b86cdb20cc1fbae458865"
        hash = "05957d98a75c04597649295dc846682d"
        hash = "33c9a47debdb07824c6c51e13740bdfe"
        
    strings:
        $cmd_PondRAT1 = "_Z7MsgDownP11_TRANS_INFO" ascii
        $cmd_PondRAT2 = "_Z5MsgUpP11_TRANS_INFO" ascii
        $cmd_PondRAT3 = "_Z6MsgRunP11_TRANS_INFO" ascii
        $cmd_PondRAT4 = "_Z6MsgCmdP11_TRANS_INFO" ascii
        
    condition:
        3 of them and filesize < 4MB
}
        