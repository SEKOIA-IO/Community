rule sekoiaio_suspicious_users_dev {
    meta:
        id = "9e8af456-6f84-4922-a262-20b8f5c8a1eb"
        version = "1.0"
        description = "Nirscord stealer"
        source = "Sekoia.io"
        creation_date = "2022-12-22"
        classification = "TLP:CLEAR"
        
    strings:
        $user1 = "\\Users\\raghus1\\" ascii
        $user2 = "\\Users\\drill\\" ascii
        $key = {58 69 b3 5f b3 87 74 f6 65 eb 96 e7 6f 4d 16 83 }
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 6MB and
        1 of ($user*) and $key
}
        