import "pe"
        
rule sekoiaio_yara_runascs {
    meta:
        id = "1720f042-2cc6-4ef1-b66c-fe8a4214366a"
        version = "1.0"
        source = "Sekoia.io"
        creation_date = "2023-08-23"
        classification = "TLP:CLEAR"
        source = "Sekoia.io"
        
    strings:
        $s1 = "RunasCs" ascii wide
        $s2 = "LOGON32_LOGON_INTERACTIVE" ascii wide
        $s3 = "LOGON32_LOGON_NETWORK" ascii wide
        $s4 = "LOGON32_LOGON_BATCH" ascii wide
        $s5 = "LOGON32_LOGON_SERVICE" ascii wide
        $s6 = "dwLogonProvider" ascii wide
        $s7 = "LogonUser" ascii wide
        $s8 = "CreateProcessAsUser" ascii wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 4MB and
        all of them and
        not (
            pe.version_info["OriginalFilename"] == "Atera.AgentPackages.CommonLib.dll" and
            for any sig in pe.signatures: (
                sig.subject contains "CN=Atera Networks Ltd" and
                sig.issuer contains "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
            )
        )
}
        