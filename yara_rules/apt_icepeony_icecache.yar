rule apt_icepeony_icecache {
    meta:
        id = "3135c70e-c925-4d26-beed-09424fc0c153"
        version = "1.0"
        description = "Detects IceCache backdoor"
        author = "Sekoia.io"
        creation_date = "2024-10-21"
        classification = "TLP:CLEAR"
        hash = "38708c33dafb5625ddde1030a7efa7db"
        hash = "1e102c8909b2bf71c626b81f7526ee01"
        hash = "34bc3c586a48f836b00aff59fe891b30"
        hash = "cd906f4cef84dddeb644b06777474b2e"
        hash = "add23fedfbf238f51173796f3feb12af"
        hash = "25b8daaa5e9c5f8820261d7ebf79f3cd"
        hash = "7fd45cc1de1230c916d5f547a9fc725c"
        hash = "e6e4060e838d7af5f13ad64258d5db0c"
        hash = "87dfc911885420380bea0cf74c8160d3"
        hash = "bd15103b300cad635191972330913d17"
        hash = "a8119b7803a6e0b8aed6bc74d9062b7f"
        hash = "e1bc3efc33b57c9e1e6d37e5011228f2"
        hash = "e1233a5f613aafec2c28133e810f536d"
        hash = "fe88a5b91841b25b4bafa08d42faab22"
        
    strings:
        $ = "Source Response Empty!"
        $ = "Source Response Len:"
        $ = "GetFromSource:"
        $ = "Failed add header!"
        $ = "Failed receive response:"
        $ = "Error: Status Code :"
        $ = "WinHttpAddRequestHeaders"
        $ = "X-FORWARDED-HOST:"
        $ = "PROXY_DEL_CONTENT"
        $ = "PROXY_CLEAR_CONTENT"
        $ = "PROXY_SET_JS"
        $ = "PROXY_GET_JS"
        $ = "PROXY_ALLOW_PC"
        $ = "Parse IP failed :"
        $ = "Clear Proxy Contents Success!"
        $ = "FILE_UPLOAD"
        $ = "FILE_DOWNLOAD"
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 1MB and
        6 of them
}
        