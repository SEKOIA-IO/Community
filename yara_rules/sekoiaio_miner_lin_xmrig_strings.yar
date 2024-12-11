rule sekoiaio_miner_lin_xmrig_strings {
    meta:
        id = "2f99020b-424c-4433-860c-5e9ab4e1f1de"
        version = "1.0"
        description = "Detects XMRig ELF"
        source = "Sekoia.io"
        creation_date = "2022-09-08"
        modification_date = "2024-01-04"
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
        uint32be(0) == 0x7f454c46 and
        filesize < 10MB and
        7 of them
}
        