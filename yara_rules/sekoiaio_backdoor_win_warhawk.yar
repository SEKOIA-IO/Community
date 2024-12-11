rule sekoiaio_backdoor_win_warhawk {
    meta:
        id = "d0ec19a7-cb08-4bca-b153-d7b0358186b4"
        version = "1.0"
        description = "Detect the WarHawk backdoor used by the SideWinder intrusion-set"
        source = "Sekoia.io"
        creation_date = "2022-10-24"
        classification = "TLP:CLEAR"
        reference = "https://www.zscaler.com/blogs/security-research/warhawk-new-backdoor-arsenal-sidewinder-apt-group-0"
        hash_exe1 = "7d3574c62df44b74337fc74ec7877792b4ffa1486a49bb19668433c3ca8836b5"
        hash_exe2 = "624c6b56ee3865f4a5792ad1946a8e86b876440a5af3bac22ac1dee92f1b7372"
        hash_iso1 = "58b3686e4255d32dbcf7dee9dac1d5be6d4692d086cde167da1e1a5e0e1b315a"
        hash_iso2 = "f97d5d3e1c2ceb3e9d23ae5b5d4e7c9857155df5acf7f67fee995cb041c797dc"
        
    strings:
        // { \"name\": \"%s\", \"size\": \"\", \"mod\": \"%s\", \"type\": \"File folder\" },
        $ = {7b205c226e616d655c223a205c2225735c222c205c2273697a655c223a205c225c222c205c226d6f645c223a205c2225735c222c205c22747970655c223a205c2246696c6520666f6c6465725c22207d2c}
        
        // { \"name\": \"%s\", \"mod\": \"%s\", \"type\": \"%s\", \"size\": \"%u\" },
        //$ = {7b205c226e616d655c223a205c2225735c222c205c226d6f645c223a205c2225735c222c205c22747970655c223a205c2225735c222c205c2273697a655c223a205c2225755c22207d2c}
        
        // { "_hwid": "%s", "_computer": "%s", "_username": "%s", "_os": "%s" }
        $ = {7b20225f68776964223a20222573222c20225f636f6d7075746572223a20222573222c20225f757365726e616d65223a20222573222c20225f6f73223a2022257322207d}
        
        // {\"name\": \"%s\", \"type\": \"%s\"},
        $ = {7b5c226e616d655c223a205c2225735c222c205c22747970655c223a205c2225735c227d2c}
        
        // { "_hwid": "%s", "_filemgr_done": "true", "_response": "%s" }
        $ = {7b20225f68776964223a20222573222c20225f66696c656d67725f646f6e65223a202274727565222c20225f726573706f6e7365223a2022257322207d}
        
        // { "_hwid": "%s", "_task": "true" }
        $ = {7b20225f68776964223a20222573222c20225f7461736b223a20227472756522207d}
        
        // { "_hwid": "%s", "_task_done": "true", "_id": "%s" }
        $ = {7b20225f68776964223a20222573222c20225f7461736b5f646f6e65223a202274727565222c20225f6964223a2022257322207d}
        
        // { "_hwid": "%s", "_cmd": "true" }
        $ = {7b20225f68776964223a20222573222c20225f636d64223a20227472756522207d}
        
        // { "_hwid": "%s", "_cmd_done": "true", "_response": "%s" }
        $ = {7b20225f68776964223a20222573222c20225f636d645f646f6e65223a202274727565222c20225f726573706f6e7365223a2022257322207d}
        
        // { "_hwid": "%s", "_filemgr": "true" }
        $ = {7b20225f68776964223a20222573222c20225f66696c656d6772223a20227472756522207d}
        
        // { "_hwid": "%s" }
        $ = {7b20225f68776964223a2022257322207d}
        
        // { "_hwid": "%s", "_ping": "true" }
        $ = {7b20225f68776964223a20222573222c20225f70696e67223a20227472756522207d}
        
        $ = "cmd.exe"
        
    condition:
        all of them
}
        