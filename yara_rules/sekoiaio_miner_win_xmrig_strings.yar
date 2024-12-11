rule sekoiaio_miner_win_xmrig_strings {
    meta:
        id = "35f203aa-20cd-4235-9ead-b34be14255d5"
        version = "1.0"
        description = "Detects XMRig EXE"
        source = "Sekoia.io"
        creation_date = "2024-01-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "XMRig "
        $ = "pool_wallet"
        $ = "IP Address currently banned"
        $ = "rigid"
        $ = "diff_current"
        $ = "shares_good"
        $ = "shares_total"
        $ = "avg_time"
        $ = "avg_time_ms"
        $ = "hashes_total"
        $ = "pool address"
        $ = "ping time"
        $ = "connection time"
        $ = "daemon+wss://"
        $ = "daemon+https://"
        $ = "daemon+http://"
        $ = "socks5://"
        $ = "stratum+ssl://"
        $ = "stratum+tcp://"
        
    condition:
        uint32be(0) == 0x5A4D and
        filesize < 15MB and
        7 of them
}
        