import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_kimsuky {
    meta:
        id = "db927d1c-34cf-4501-a6ce-3e8ecdefc5a3"
        version = "1.0"
        description = "Detect the backdoors used by Kimsuky based on specific PE ressources"
        source = "Sekoia.io"
        creation_date = "2024-06-04"
        classification = "TLP:CLEAR"
        hash1 = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"
        hash2 = "cca1705d7a85fe45dce9faec5790d498427b3fa8e546d7d7b57f18a925fdfa5d"
        
    condition:
        uint16be(0) == 0x4d5a
        and for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "3d570af85db2bb18265d80e7209a5c90f7cc82e0c868c0088a925df6f34e9066"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "3d570af85db2bb18265d80e7209a5c90f7cc82e0c868c0088a925df6f34e9066"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ac9ed305c6dac749163db359736e7d92fca9173ff5c9e1f021d500b306e3c5ec"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "0ca965ccf7324b098da617909d38986c1e6aae3e12d9629975f1815ed4ed3907"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "25d79e59a6b625e5c22ccb55cc49373d38cc6f20cb75504b0df1bc0804bb1247"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ce5619ffe04ec569bf2565e0964156378bda7c42eb646bedbac2191a5af7bebf"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ce10e65f7bf105fc06005340f0a8eaea9b351f3750d2818c1cf2ca25a7f495be"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "5a9e2a392c530ab8b38ff917ae0f28496107f1bde94e89515931fd29a0bfb2e5"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "19f4f3a05b809d8e33bb0004f62899ca5f9eac7e4cdba68dfd5c0a6f2d71bec3"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "b9c208b9bada7bac4d5bfe53992f570e34e0b4d5cfa0862de9847ddf5630ab9a"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "3d570af85db2bb18265d80e7209a5c90f7cc82e0c868c0088a925df6f34e9066"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ac9ed305c6dac749163db359736e7d92fca9173ff5c9e1f021d500b306e3c5ec"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "0ca965ccf7324b098da617909d38986c1e6aae3e12d9629975f1815ed4ed3907"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "25d79e59a6b625e5c22ccb55cc49373d38cc6f20cb75504b0df1bc0804bb1247"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ce5619ffe04ec569bf2565e0964156378bda7c42eb646bedbac2191a5af7bebf"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "ce10e65f7bf105fc06005340f0a8eaea9b351f3750d2818c1cf2ca25a7f495be"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "5a9e2a392c530ab8b38ff917ae0f28496107f1bde94e89515931fd29a0bfb2e5"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "19f4f3a05b809d8e33bb0004f62899ca5f9eac7e4cdba68dfd5c0a6f2d71bec3"
            or hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "b9c208b9bada7bac4d5bfe53992f570e34e0b4d5cfa0862de9847ddf5630ab9a"
        )
}
        