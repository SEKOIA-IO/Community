rule apt_polonium_powershell_creepydrive_strings {
    meta:
        id = "0ba196bd-9cd6-4553-b7bf-69989cdb8be4"
        version = "1.0"
        description = "Detects POLONIUM CreepyDrive Powershell implant"
        author = "Sekoia.io"
        creation_date = "2022-06-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "function Exec($comm)" base64 ascii  wide
        $ = "$comm = $comm + \"| outstring" base64 ascii  wide
        $ = "Invoke-Expression -Command:$comm" base64 ascii  wide
        $ = "microsoft.com" base64 ascii  wide
        $ = "$req = Invoke-WebRequest" base64 ascii  wide
        $ = "$j += $data" base64 ascii  wide
        $ = "$res = Exec($arr[$i])" base64 ascii  wide
        $ = "$arr = @(iex \"$req\")" base64 ascii  wide
        $ = "elseif ($req -cmatch" base64 ascii  wide
        $ = "graph.microsoft.com" base64 ascii  wide
        
    condition:
        3 of them
}
        