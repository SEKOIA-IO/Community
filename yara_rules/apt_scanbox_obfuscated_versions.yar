rule apt_scanbox_obfuscated_versions {
    meta:
        id = "2866cead-7f16-4895-80ef-aad6fb66e864"
        version = "1.0"
        description = "Detects obfuscated versions of the scanbox framework"
        author = "Sekoia.io"
        creation_date = "2022-09-01"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$_$_$_$__$_____$__$_$_$_$__$"
        $ = "NztCm_NcDkh"
        $ = "____$_$__$__$_______w____$_$__$__$_____i____$_$__$__$_____"
        $ = "391,379,398,381,386"
        $ = "plguinurl"
        $ = "plugin_timeout*1000"
        
    condition:
        2 of them and filesize < 500KB
}
        