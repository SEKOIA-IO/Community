rule apt_MuddyWater_malicious_pdf {
    meta:
        id = "77983aea-47cb-4436-b773-faf7be430339"
        version = "1.0"
        intrusion_set = "MuddyWater"
        description = "Detects malicious PDF used by MuddyWater"
        source = "Sekoia.io"
        creation_date = "2024-06-10"
        classification = "TLP:WHITE"
    strings:
        $ = "egnyte.com/fl/"
        $ = "/Type/Pages/Count 1"
    condition:
        uint32be(0) == 0x25504446 and
        filesize < 300KB and
        all of them
}
