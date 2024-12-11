rule sekoiaio_unk_quad7_fsynet_strings {
    meta:
        id = "897b2421-c177-48c0-8f5b-82d8434208cb"
        version = "1.0"
        description = "Matches node-r-control, asr_node, node-relay"
        source = "Sekoia.io"
        creation_date = "2024-08-20"
        classification = "TLP:CLEAR"
        hash = "f42849076e24b7827218f7a25bc11ccc"
        hash = "b3b09819f820a4ecd31f82f369000af2"
        hash = "92093dd7ba6ae8fe34a215c4c4bd1cd4"
        hash = "e6f6a6de285d7c2361c32b1f29a6c3f6"
        hash = "408152285671bbd0e6e63bd71d6abaaf"
        hash = "5efc7d824851be9ec90a97d889a40d23"
        
    strings:
        $ = "prev_hop_port"
        $ = "next_hop_port"
        $ = "back_hop_port"
        $ = "next_tsn_port"
        $ = "prev_hop_ip"
        $ = "next_hop_ip"
        $ = "back_hop_ip"
        $ = "next_tsn_ip"
        $ = "ikcp_"
        $ = "/tmp/log_r"
        $ = "total_hop"
        
    condition:
        uint32be(0) == 0x7f454c46
        and filesize < 5MB
        and 6 of them
}
        