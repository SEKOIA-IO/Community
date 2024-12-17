rule sekoiaio_backdoor_win_rollsling {
    meta:
        id = "5ef23b9c-5bc5-4f02-b1b4-1af18a03241a"
        version = "1.0"
        description = "Detect Lazarus' RollSling malware (aka LazarLoader)"
        author = "Sekoia.io"
        creation_date = "2023-10-24"
        classification = "TLP:CLEAR"
        hash1 = "d9add2bfdfebfa235575687de356f0cefb3e4c55964c4cb8bfdcdc58294eeaca"
        hash2 = "48538a935ddf2cbeb4918d0ccf9372ec8e0a57c5fd145a584a9b1bb4ebbcd5ce"
        hash3 = "18825be6b269087d7699f3d0aa2e6db2ae72ded36c56aa8e7b8a606dde3741fa"
        hash4 = "645205e38dfdd560f6242ba717af1bfdd8e85baf5e710d724b853fe9808c4551"
        hash5 = "455bab490a300d9d63b8777c223287c0a6a647ca7b98b96fd3236f83b8adc77b"
        reference = "https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/"
        
    strings:
        $s1 = "LookupPrivilegeVCreateRemoteThreAdjustTokenPriviOpenProcessToken"
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        