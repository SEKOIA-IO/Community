rule infrastructure_iclickfix_cluster_ic_tracker_js_wordpress {
   meta:
       description = "Find WordPress HTML compromised by the IClickFix cluster, that injects the ic-tracker-js HTML tag"
       source = "Sekoia.io"
       reference = "https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/" 
       creation_date = "2025-12-04"
       modification_date = "2025-12-04"
       classification = "TLP:CLEAR"

   strings:
       $wp01 = "\" id=\"ic-tracker-js\"" ascii

   condition:
       all of them
}
