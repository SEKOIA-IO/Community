rule infrastructure_iclickfix_cluster_ic_tracker_html_lure {
    meta:
        description = "Find the HTML lure used by the IClickFix cluster, impersonating Cloudflare Turnstile CAPTCHA"
        source = "Sekoia.io"
        reference = "https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/"
        creation_date = "2025-12-04"
        modification_date = "2025-12-04"
        classification = "TLP:CLEAR"

    strings:
        //HTML page containing JavaScript and a second HTML corresponding to the ClickFix lure
        $lure01 = "let clickCopy" ascii
        $lure02 = "let clickCounts" ascii
        $lure03 = "let delay" ascii
        $lure04 = "let COPYbase64Text" ascii
        $lure05 = "let rayID" ascii
        $lure06 = "'Cloudflare protection – verify with code:" ascii
        $lure07 = "center.innerHTML" ascii
        $lure08 = "Verify you are human" ascii
        $lure09 = "location.host + " ascii
        $lure10 = "needs to review the security of your connection before proceeding." ascii
        $lure11 = "Unusual Web Traffic Detected" ascii
        $lure12 = "Our security system has identified irregular web activity" ascii
        $lure13 = "originating from your IP address. Automated verification" ascii
        $lure14 = "unable to confirm that you are a legitimate user." ascii
        $lure15 = "This manual verification step helps us ensure that your connection" ascii

    condition:
        9 of ($lure*)
}
