rule apt_mustangpanda_mqsttang_qmagent {
    meta:
        id = "bcf6f961-0d9b-4fbc-81d2-f5d00c68d4d5"
        version = "1.0"
        description = "Detects specifics string of MQsTTang, also known as QMAGENT"
        author = "Sekoia.io"
        creation_date = "2023-03-27"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "iot/server"
        $s2 = "QMQTT::Message"
        $s3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $command1 = "c_topic"
        $command2 = "Alive"
        $command3 = "msg"
        $command4 = "ret"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 8MB  and
        all of them
}
        