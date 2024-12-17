rule sekoiaio_tool_enum4linux_strings {
    meta:
        id = "6b3094fe-1292-4da3-a1ed-9e255be531da"
        version = "1.0"
        description = "Detects enum4linux based on strings"
        author = "Sekoia.io"
        creation_date = "2024-02-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "my $os_info = `$command`;"
        $ = "($global_workgroup) = $os_info =~"
        $ = "sub enum_groups {"
        $ = "if ($shares =~ /NT_STATUS_ACCESS_DENIED/) {"
        $ = "Can't open share list file $shares_file"
        $ = "my $users = `$command`;"
        $ = "my @shares = <SHARES>;"
        $ = "foreach my $grouptype (\"builtin\", \"domain\") {"
        
    condition:
        6 of them
}
        