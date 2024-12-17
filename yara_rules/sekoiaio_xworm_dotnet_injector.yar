rule sekoiaio_xworm_dotnet_injector {
    meta:
        id = "50581a9d-afc3-43da-9e34-3a553cbd01b4"
        version = "1.0"
        description = ".NET injector used by XWorm TA"
        author = "Sekoia.io"
        creation_date = "2022-12-02"
        classification = "TLP:CLEAR"
        
    strings:
        $first_payload = "jBGIcSr2fKhj1ZT2YNLBTcYYeAw/vWUT98dCA/H6hpI+dY+lkoSe1ATx7XEIXKtAdTSwl1PKhNROoxstXsnsHTZbS2ikRLv6lmHd5v09DltsPeXIOA789wZC8qR1OScJFohGxuWQSQ8K2TAFUQAntIFdX+Om1QZUARdDnb4f+P8VFucU9avWD75yK1IcTDDDEYwvm/rwUYTqWitcrfIY+aFcgQwyvEzkN7Pbsah4Kts+XmK0C3TzlnDd2mz6TdsPphGbBxcbBdZGMTyzunZUEKRYea7xM6u+az9v7m6a1G6vhsSqz4C/nleDmzL2dIVnVR6Ni6+0hlExcP" wide
        $rijndael_key1 = { e5 a0 b1 e8 89 be e8 8e 8e e4 bb a3 e5 ba b5 e9 85 8d e7 89 b9 e6 b0 8f e5 85 8b e9 9b 99 e8 89 be e5 8b 92 e6 8b 89 e6 a1 83 e9 ad 9a e6 88 91 e6 96 af e6 a1 83 e5 ba 95 e5 be b7 }
        $rijndael_key2 = { e7 9b 9f e7 91 aa e6 a1 83 e9 87 91 e5 90 89 e9 97 95 e5 a0 b1 e9 9b 99 e9 97 95 e5 96 ac e5 ba 95 e5 a0 b1 e5 be b7 e6 8b 89 e5 92 8c e7 a0 b4 e7 88 be e9 a6 ac e6 88 91 e5 8a a0 }
        $rijndael_key3 = { e6 9b b2 e6 b0 8f e5 ba b5 e5 a3 ab e9 97 95 e5 be b7 e6 96 af e8 9b 8b }
        $s1 = "fullofdick"
        $s2 = "holdmeback"
        $s3 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" wide
        
    condition:
        ($first_payload  and all of ($rijndael_key*)) or 2 of ($s*)
}
        