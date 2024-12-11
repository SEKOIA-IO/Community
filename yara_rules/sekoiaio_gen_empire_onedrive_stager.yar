rule sekoiaio_gen_empire_onedrive_stager {
    meta:
        id = "2053416f-1f53-491e-9c70-787a04362d16"
        version = "1.0"
        description = "Detects the Empire OneDrive stager"
        source = "Sekoia.io"
        creation_date = "2022-01-26"
        classification = "TLP:CLEAR"
        
    strings:
        $sleep = "Start-Sleep -Seconds $(($PI -as [Int])*2)" wide ascii nocase
        $down  = "wc.DownloadData" wide ascii nocase
        
    condition:
        $down in (@sleep..@sleep+1000)
}
        