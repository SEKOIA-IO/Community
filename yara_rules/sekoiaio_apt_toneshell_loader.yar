rule sekoiaio_apt_toneshell_loader {
    meta:
        id = "b4bf284b-cab6-455e-a1c1-ad341d43bfdd"
        version = "1.0"
        description = "Detects loader of ToneShell (exception based)"
        source = "Sekoia.io"
        creation_date = "2024-10-02"
        classification = "TLP:CLEAR"
        hash = "41e0d172d900344a3692b88fff7527d9"
        hash = "782cf7183735935f3f7aad041cec3184"
        hash = "97c1f436028c58b51d4c92ee9c9ce424"
        hash = "d6c771f2afd8ce35e8727f95f3a3c6c4"
        hash = "b8520c5bad88ade394086cb7b1b7b631"
        hash = "0b3e8571e70a32490da19f6b3283151c"
        hash = "f6784c65ee115a9ae4c0fb03e0045285"
        hash = "38888696e5223c77f5f8680922396123"
        hash = "b52d0707e4e5d5c0d5fd5f5a177ba712"
        hash = "fd54c6d17ff91640b377ff41353efdaa"
        hash = "a6efe263acc794a212647a96e52ddf1f"
        hash = "6e8c80c5f2f9a1da504618e984d2a56c"
        hash = "0839666697ccc562a9c1fe77d6755931"
        hash = "f367f2fe580e556176b60da202c742a5"
        hash = "e8b2fcc14494ada2f28d1f6ecd2521a2"
        hash = "c08589e10812cc7d636dcbe2a36d43b4"
        hash = "fa848a05cfecc0c25cd21364c9516584"
        hash = "be231f7879d8d2159b67b7f277527268"
        hash = "2acd8b48202dcc30d88a871370c4f37a"
        hash = "72963bfc2837695f038680471d4f061c"
        
    strings:
        $exception = {00 00 00 00 2e 44 00 00}
        $code = {02 00 00 00 66 89 96}
        $kernel32 = "Kernel32.dll" wide
        $outputdbgstr = "OutputDebugStringA"
        $content = "ResetEvent"
        
    condition:
        uint16be(0) == 0x4d5a and
        all of them and filesize < 2MB
}
        