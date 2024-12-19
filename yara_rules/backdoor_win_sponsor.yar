rule backdoor_win_sponsor {
    meta:
        id = "d410cdb7-a2a8-481e-a90a-49ef15a7a0e3"
        version = "1.0"
        description = "Detect the Sponsor backdoor"
        author = "Sekoia.io"
        creation_date = "2024-03-29"
        classification = "TLP:CLEAR"
        reference = "https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/"
        hash1 = "e5ee874bd59bb2a6dec700686544e7914312abff166a7390b34f7cb29993267a"
        hash2 = "e2b74ed355d68bed2e7242baecccd7eb6eb480212d6cc54526bc4ff7e6f57629"
        hash3 = "2a99cf7d73d453f3554e24bf3efa49d8109da9e8543db815a8f813559d083f8f"
        hash4 = "c4dbda41c726af9ba3d9224f2e38fc433d2b60f4a23512437adeae8ef8986c57"
        
    strings:
        $ = "Content-Type: application/x-www-form-urlencoded"
        $ = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"
        $ = "\\Uninstall.bat"
        $ = "\\config.txt"
        $ = "\\node.txt"
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        