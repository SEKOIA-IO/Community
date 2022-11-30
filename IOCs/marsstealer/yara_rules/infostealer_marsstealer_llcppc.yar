import "pe"

rule infostealer_win_mars_stealer_llcppc {
    meta:
        description = "Identifies samples of Mars Stealer based on the PE section name LLCPPC."
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/mars-a-red-hot-information-stealer/"
        classification = "TLP:WHITE"
        hash = "fd92fe8a4534bc6e14e177fee38a13f771a091fa6c7171fcee2791c58fbecf40"

    condition:
        uint16(0)==0x5A4D and
        for any i in ( 0..pe.number_of_sections-1 ): (
                pe.sections[i].name == "LLCPPC" and pe.sections[i].raw_data_size < 5000 )
}
